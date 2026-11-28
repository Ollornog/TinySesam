"""Built-in login/auth views (dark/light) — and the template registry through which
EVERY page can be replaced.

Frontend fully replaceable:
    auth.set_template("login", my_login_function)   # fn(auth, ctx) -> str | Response
The built-in renderers stay as fallback. `ctx` is a dict with all variables of the page
(documented per renderer). If an override returns a Starlette `Response`, it is delivered
unchanged; a string is wrapped as HTML with the respective status.
"""
from __future__ import annotations
import html
import json
import re
from urllib.parse import quote as _quote

from . import dialog as _dialog
from . import topbar as _topbar
from .theme import FAVICON_SVG, TOKENS, c22_css, c22_head, theme_head

# `<link rel=stylesheet>` too (c22_stylesheet, brand_head): under 'strict' a same-origin stylesheet loads only with the nonce.
_NONCE_TAG = re.compile(r'<(script|style|link(?=[^>]*\brel=["\']?stylesheet\b))(?![^>]*\bnonce=)(?=[\s>])')


def inject_nonce(html_str: str, nonce: str) -> str:
    """Give every `<script>`/`<style>`/`<link rel=stylesheet>` without its own nonce the response's nonce (CSP 'strict').

    Here and not in the manager: the admin panel needs the same function, and an import from the
    manager would make `admin` ↔ `manager` an import cycle."""
    return _NONCE_TAG.sub(rf'<\g<1> nonce="{nonce}"', html_str)


class Templates:
    """Registry of named page renderers. `render(name, auth, ctx)` takes an override
    (if set) or the built-in default."""
    def __init__(self):
        self._overrides: dict = {}

    def set(self, name: str, fn):
        """Override a renderer. fn(auth, ctx) -> str | Response."""
        self._overrides[name] = fn

    def has(self, name: str) -> bool:
        return name in self._overrides or name in DEFAULTS

    def overridden(self, name: str) -> bool:
        """Has the app replaced this page with its own template?"""
        return name in self._overrides

    def render(self, name: str, auth, ctx: dict):
        fn = self._overrides.get(name) or DEFAULTS.get(name)
        if fn is None:
            raise KeyError(f"no template '{name}'")
        return fn(auth, ctx)


#: Placeholder before every path of the app in the built-in pages (forms, links, fetch calls).
#: `TinySesam.render_page` inserts the mount prefix (`root_path`) for it (T-15); a custom
#: template that does not name it stays untouched.
PREFIX_PLACEHOLDER = "__TS_P__"

_CSS = TOKENS + """
/* IMPORTANT: everything below is scoped to .tsmain. Otherwise the card CSS bleeds onto the host
   app's `brand_header` and `brand_footer` (bare button/input/h1 selectors). */
*{box-sizing:border-box}
body{font-family:var(--ts-font);margin:0;min-height:100vh;display:flex;flex-direction:column;
     background:var(--ts-bg);color:var(--ts-ink)}
.tsmain{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;
     gap:14px;padding:32px 16px}
.tsmain .card{width:340px;max-width:92vw;background:var(--ts-surface);border:1px solid var(--ts-line);
     border-radius:calc(var(--ts-radius) + 2px);padding:26px}
.tsmain h1{font-size:20px;margin:0 0 18px;text-align:center}
.tsmain .app-icon{display:block;margin:0 auto 12px;border-radius:10px;object-fit:contain}
.tsmain label{display:block;font-size:12px;color:var(--ts-muted);margin:12px 0 4px}
.tsmain input{width:100%;background:var(--ts-field-bg);color:var(--ts-ink);
     border:1px solid var(--ts-field-line);border-radius:8px;padding:10px 12px;font-size:15px}
.tsmain button,.tsmain .btn2{width:100%;margin-top:18px;padding:11px;border:0;border-radius:8px;
     font-size:15px;cursor:pointer;background:var(--ts-accent);color:var(--ts-accent-ink);
     display:block;text-align:center;text-decoration:none}
.tsmain .btn2{background:var(--ts-neutral);color:var(--ts-neutral-ink);margin-top:10px}
.tsmain .tsweiter{height:4px;margin-top:12px;border-radius:2px;background:var(--ts-line);overflow:hidden}
.tsmain .tsweiter i{display:block;height:100%;width:100%;background:var(--ts-accent);transform-origin:left}
@media(prefers-reduced-motion:reduce){.tsmain .tsweiter{display:none}}
.tsmain .err{background:var(--ts-err-bg);color:var(--ts-err-ink);padding:9px 12px;border-radius:8px;
     font-size:13px;margin-bottom:6px}
.tsmain .ok{background:var(--ts-ok-bg);color:var(--ts-ok-ink);padding:9px 12px;border-radius:8px;
     font-size:13px;margin-bottom:6px}
.tsmain .or{text-align:center;color:var(--ts-muted);font-size:12px;margin:16px 0 4px}
.tsmain .hint{color:var(--ts-muted);font-size:12px;text-align:center;margin-top:14px}
.tsmain .hint a{color:var(--ts-muted)}
.tsmain p.app{color:var(--ts-muted);text-align:center;margin:-6px 0 18px}
.tsmain .remember{display:flex;align-items:center;gap:7px;margin-top:14px;font-size:13px;
     color:var(--ts-muted)}
.tsmain .remember input{width:auto;margin:0}
.tsmain .code{width:100%;text-align:center;letter-spacing:.4em;font-size:22px}
.tsmain img.qr{display:block;margin:14px auto;width:190px;height:190px;background:#fff;
     border-radius:8px;padding:6px}
.tsmain .mono{font-family:var(--ts-mono);background:var(--ts-field-bg);
     border:1px solid var(--ts-field-line);border-radius:6px;padding:6px 8px;font-size:13px;
     text-align:center;word-break:break-all}
.tsmain .mono.qrcode{font-size:22px;letter-spacing:.15em;margin:8px 0}
.tsmain .mono.rccodes{white-space:pre;margin:8px 0}
.tsmain .rccopyrow{display:flex;align-items:center;gap:10px}
.tsmain .rccopyrow .btn2{width:auto;margin-top:0;padding:8px 16px}
.tsmain .rcstate{font-size:12px;color:var(--ts-ok-ink)}
.tsmain .rcstate.manual{color:var(--ts-warn-ink)}
.tsmain table.qrinfo{width:100%;border-collapse:collapse;font-size:13px;margin:12px 0 0}
.tsmain table.qrinfo th{text-align:left;color:var(--ts-muted);font-weight:600;padding:4px 10px 4px 0;
     vertical-align:top;white-space:nowrap}
.tsmain table.qrinfo td{padding:4px 0;word-break:break-word}
.tsmain form.qrstart{margin:0}
.tsmain .warnbar{background:var(--ts-warn-bg);color:var(--ts-warn-ink);padding:9px 12px;
     border-radius:8px;font-size:12px;margin-bottom:10px}
/* Messages (PO 2026-10-08): a box of their own BELOW the card, one icon per message. Notice, warning and
   error are built alike and differ only in colour and icon. */
.tsmain .notices{width:340px;max-width:92vw;display:flex;flex-direction:column;gap:8px}
.tsmain .notice{display:flex;align-items:flex-start;gap:10px;padding:11px 14px;font-size:13px;line-height:1.4;
     border-radius:calc(var(--ts-radius) + 2px);border:1px solid var(--ts-line)}
.tsmain .notice svg{flex:0 0 18px;width:18px;height:18px;margin-top:1px}
.tsmain .notice.info{background:var(--ts-info-bg);color:var(--ts-info-ink)}
.tsmain .notice.warn{background:var(--ts-warn-bg);color:var(--ts-warn-ink)}
.tsmain .notice.error{background:var(--ts-err-bg);color:var(--ts-err-ink)}
.tsmain .notice.ok{background:var(--ts-ok-bg);color:var(--ts-ok-ink)}
/* sits NEXT TO the card, not in it — a demo notice is not part of the form */
.tsmain .demobar{width:340px;max-width:92vw;background:var(--ts-info-bg);color:var(--ts-info-ink);
     padding:11px 14px;border-radius:calc(var(--ts-radius) + 2px);border:1px solid var(--ts-line);
     font-size:12.5px;line-height:1.5}
.tsmain .demobar b{font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.tsmain .demobar button.demofill{width:auto;display:inline;margin:0;padding:1px 7px;border-radius:6px;
     font:inherit;font-weight:700;background:var(--ts-chip);color:var(--ts-info-ink);
     border:1px solid var(--ts-line);cursor:pointer}
.tsmain .demobar button.demofill:hover{filter:brightness(1.08)}
.tsmain .demowarn{margin-top:6px;color:var(--ts-warn-ink);background:var(--ts-warn-bg);padding:6px 8px;
     border-radius:6px;font-size:11.5px}
.tsmain .demowarn code{background:none;border:0;padding:0}
/* Error page (_error): replaces earlier inline styling — a CSP nonce does not cover
   attribute styles, only <style> blocks. */
.tsmain .errcode{font-size:52px;margin:.1em 0}
.tsmain .errhint{font-size:14px;margin-top:0}
"""


#: Built-in favicon (since 0.24.8, new mark in T-64): a rounded tile with a keyhole ("open sesame") — the same
#: shape as the top bar's logo (`topbar._MARK`), colours in `theme.FAVICON_SVG` (the one place for colours). As a
#: data: URI, so without a fetch. Without a favicon the browser requests /favicon.ico; behind a gate that is a
#: protected path.
STANDARD_FAVICON = "data:image/svg+xml;base64," + __import__("base64").b64encode(FAVICON_SVG.encode()).decode()


def favicon_link(icon: str) -> str:
    """Favicon `<link>` for the built-in pages. One place, so no page forgets it. Empty = the built-in
    default icon, "none" = none."""
    if icon == "none":
        return ""
    return f"<link rel=icon href='{html.escape(icon or STANDARD_FAVICON)}'>"


def background(cfg) -> tuple[str, str]:
    """(CSS, HTML) of the rotating background images from `brand_backgrounds` — empty if none are set. The image
    sits in the (nonce-protected) page `<style>`, not in style=: the strict CSP forbids inline attributes."""
    images = [b for b in (getattr(cfg, "brand_backgrounds", None) or []) if b]
    if not images:
        return "", ""
    # f = cross-fade time between two images. All delays are pulled forward by (f − 0.5 s): the first image appears after
    # half a second, instead of emerging from black only after f seconds (PO 2026-10-09).
    n, d, f = len(images), int(getattr(cfg, "brand_background_seconds", 12) or 12), 3
    t = n * d
    css = [".tsbg{position:fixed;inset:0;z-index:-1;background:var(--ts-image-base);overflow:hidden}",
           (".tsbg i{position:absolute;inset:-2%;background:center/cover no-repeat;opacity:0;"
            "filter:grayscale(.25) brightness(var(--ts-image-brightness))}"),
           (".tsbg::after{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at center,"
            "var(--ts-image-overlay),var(--ts-image-overlay-edge))}"),
           "body{background:transparent}",
           (".tsbg-source{position:fixed;right:12px;bottom:8px;font-size:11px;color:var(--ts-muted);opacity:.55;"
            "text-decoration:none}.tsbg-source:hover{opacity:.9;text-decoration:underline}")]
    if n == 1:
        css.append(".tsbg i{opacity:var(--ts-image-strength)}")
    else:
        a, b, c = f / t * 100, d / t * 100, (d + f) / t * 100
        css.append(f"@keyframes tsbg{{0%{{opacity:0}}{a:.3f}%{{opacity:var(--ts-image-strength)}}"
                   f"{b:.3f}%{{opacity:var(--ts-image-strength)}}"
                   f"{c:.3f}%{{opacity:0}}100%{{opacity:0}}}}")
        css.append(f".tsbg i{{animation:tsbg {t}s linear infinite}}")
        css.append("@media(prefers-reduced-motion:reduce){.tsbg i{animation:none}.tsbg i:first-child{opacity:var(--ts-image-strength)}}")
    for k, b in enumerate(images, 1):
        css.append(f".tsbg i:nth-child({k}){{background-image:url('{b}')"
                   + (f";animation-delay:{(k - 1) * d - (f - 0.5):g}s" if n > 1 else "") + "}")
    source = ""
    text, destination = getattr(cfg, "brand_background_credit_text", ""), getattr(cfg, "brand_background_credit_url", "")
    if text:
        source = (f"<a class=tsbg-source href='{html.escape(destination)}' target=_blank rel='noopener noreferrer'>"
                  f"{html.escape(text)}</a>" if destination else f"<span class=tsbg-source>{html.escape(text)}</span>")
    return "".join(css), "<div class=tsbg aria-hidden=true>" + "<i></i>" * n + "</div>" + source


def brand(value, auth):
    """`brand_header`/`brand_footer` may be a string or `fn(auth) -> str` — the latter
    when the body depends on the request (login state, language)."""
    if callable(value):
        try:
            return value(auth) or ""
        except Exception:      # a broken body must not take the login page down with it
            return ""
    return value or ""


def _doc(title, body, lang="en", brand_css="", brand_head="", card=True, brand_icon="", top="",
         header="", footer="", below="", hg=("", ""), head="", bar=""):
    """`top` sits outside the card (e.g. the demo notice) — directly above it, same width; `below` directly
    below it (the messages). `header`/`footer` enclose the page so the host app can put its navigation
    around it; `bar` (the top bar, T-64) sits inside that frame, above the content. `head` lands in `<head>`
    before the branding (e.g. a meta refresh). The light/dark restore comes first, before any style."""
    inner = (f"<div class=card>{body}</div>" if card else body) + (below or "")
    return (f"<!doctype html><html lang={html.escape(lang)}><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>{theme_head()}"
            f"{favicon_link(brand_icon)}{head}"
            f"<title>{html.escape(title)}</title><style>{_CSS}{hg[0]}{brand_css or ''}</style>{brand_head or ''}</head>"
            f"<body>{hg[1]}{header}{bar}<div class=tsmain>{top}{inner}</div>{footer}</body></html>")


def _shell(title, body, lang="en"):
    return _doc(title, body)


def _bar(auth, ctx, current="") -> str:
    """The top bar (T-64) with its CSS/JS — with the account menu when the page's ctx names a signed-in `viewer`
    (`render_page` looks it up for the pages of `topbar.MENU_PAGES`), otherwise logo and name only.
    Empty with `topbar_enabled=False`."""
    if not getattr(auth.cfg, "topbar_enabled", True):
        return ""
    ctx = ctx or {}
    # The app frame (T-91): `render_page` puts the frame of the host a person comes from into ctx["frame"].
    # The layout (T-103): `apps[id].layout` of the framing application's host, else `shell_layout`.
    if ctx.get("frame"):
        layout = _topbar.layout_for(auth, ctx["frame"]["host"])
        return (_topbar.render_frame(auth, ctx["frame"], viewer=ctx.get("viewer"), csrf=ctx.get("csrf", ""),
                                     current=current, layout=layout) + _topbar.assets())
    return (_topbar.render(auth, viewer=ctx.get("viewer"), csrf=ctx.get("csrf", ""), current=current,
                           layout=_topbar.layout_for(auth)) + _topbar.assets())


def _app_q(ctx, sep: str = "?") -> str:
    """`app=<host>` of the page's app frame (T-91) for an internal link, so the next page stays framed — empty without
    a frame. `sep` is "?" or "&" (already HTML-escaped by the caller where needed)."""
    frame = (ctx or {}).get("frame")
    return f"{sep}app={_quote(frame['host'], safe='')}" if frame else ""


def _page(auth, title, body, card=True, top="", below="", head="", ctx=None, current=""):
    """Like _shell, but with branding from the config (brand_css/brand_head/brand_icon/brand_header/
    brand_footer) — re-skins and frames all pages centrally. `top` lands above the card, `below` below it.
    `ctx` feeds the top bar (viewer, csrf); `current` marks the menu entry of this page."""
    cfg = auth.cfg
    header, footer = brand(getattr(cfg, "brand_header", ""), auth), brand(getattr(cfg, "brand_footer", ""), auth)
    bar = _bar(auth, ctx, current)
    # The application's own layout (T-104, `page_layout`): its head, header and footer around the page; with a header
    # TinySesam's bar gives way to the application's navigation. Its blocks get the nonce in `render_page`.
    layout = (ctx or {}).get("page_layout")
    if layout:
        head = layout["head"] + head
        if layout["header"]:
            header, bar = layout["header"], ""
        if layout["footer"]:
            footer = layout["footer"]
    return _doc(title, body, cfg.lang, c22_css(cfg) + (getattr(cfg, "brand_css", "") or ""),
                c22_head(cfg) + (getattr(cfg, "brand_head", "") or ""),
                card, getattr(cfg, "brand_icon", ""), top, header, footer, below,
                background(cfg), head, bar)


#: Message icons — inline SVG in currentColor (nothing is fetched), 24 grid, strokes only.
_SYMBOL = {
    "info": "<circle cx='12' cy='12' r='9'/><path d='M12 11v5'/><path d='M12 7.5v.5'/>",
    "warn": "<path d='M12 3.5 21 19.5H3z'/><path d='M12 10v4'/><path d='M12 16.5v.5'/>",
    "error": "<circle cx='12' cy='12' r='9'/><path d='M8.5 8.5l7 7'/><path d='M15.5 8.5l-7 7'/>",
    "ok": "<circle cx='12' cy='12' r='9'/><path d='M8 12.5l2.8 2.8L16 10'/>",
}


def _messages(items) -> str:
    """Messages as a separate box below the card: `[(kind, text), …]`, kind ∈ info | ok | warn | error.
    Empty texts are dropped; without a message there is no box."""
    parts = []
    for kind, text in items:
        if not text:
            continue
        kind = kind if kind in _SYMBOL else "info"
        role = "alert" if kind == "error" else "status"
        parts.append(f"<div class='notice {kind}' role={role}>"
                     f"<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' "
                     f"stroke-linejoin='round' aria-hidden='true'>{_SYMBOL[kind]}</svg><span>{_e(text)}</span></div>")
    return f"<div class=notices>{''.join(parts)}</div>" if parts else ""


def _e(s) -> str:
    return html.escape(str(s or ""))


def _next_q(s) -> str:
    """A `next` target as ONE query value, for links and script strings (B-3).

    `_e` is the escaping for HTML text and attributes — it leaves `&`, `+`, `%`, `;` and `#` alone,
    which in a query string have a meaning of their own: `?next=/a?x=1&y=2` lost `&y=2`, `+` came back
    as a space, `%3B` as `;` — the person landed on another file than the one requested (and
    `&amp;` in a file name even went through `_e` twice). Percent-encoding everything leaves only
    `[A-Za-z0-9_.~%-]`, which is safe in an HTML attribute and in a JS string as well. The server decodes
    exactly once and still runs `safe_next` on the result — encoding changes nothing about what is allowed.
    """
    return _quote(str(s or ""), safe="")


def _ident(auth) -> tuple[str, str]:
    """Label + autocomplete for the identifier field, depending on `config.login_identifier`."""
    mode = getattr(auth.cfg, "login_identifier", "both")
    if mode == "email":
        return auth.t("login.email"), "email"
    if mode == "username":
        return auth.t("login.user"), "username"
    return auth.t("login.identifier"), "username"


# A click on a name puts the credentials into the form. And: a password filled in by the browser
# is discarded — otherwise you type the username over the autofill default and the
# login fails with "wrong credentials" without you seeing the reason.
_DEMO_JS = """<script>
(function(){
  // Browsers fill in saved passwords at different times — so clear repeatedly.
  // As soon as someone types themselves, nothing is cleared any more.
  var typed = false;
  function clear(){
    if(typed) return;
    document.querySelectorAll('form input[type=password]').forEach(function(f){ f.value = ''; });
  }
  function init(){
    document.querySelectorAll('form input').forEach(function(f){
      f.addEventListener('input', function(){ typed = true; });
    });
    [0, 80, 250, 700].forEach(function(ms){ setTimeout(clear, ms); });
    document.querySelectorAll('.demofill').forEach(function(b){
      b.addEventListener('click', function(){
        typed = true;
        var form = document.querySelector('form');
        var u = form.querySelector('[name=username]'), p = form.querySelector('[name=password]');
        if(u) u.value = b.dataset.u;
        if(p) p.value = b.dataset.p;
        (p || u).focus();
      });
    });
  }
  if(document.readyState !== 'loading') init(); else document.addEventListener('DOMContentLoaded', init);
  addEventListener('pageshow', function(e){ if(e.persisted) clear(); });   // back button
})();
</script>"""


def _fill(user, pw) -> str:
    return f"<button type=button class=demofill data-u='{_e(user)}' data-p='{_e(pw)}'>{_e(user)}</button>"


def _demobar(auth, pin=False, ctx=None) -> str:
    """Credentials + unmistakable warning — only if `demo_mode` is on.
    `ctx['demo_hint']=False` suppresses it (e.g. in a preview, where it only gets in the way)."""
    cfg = auth.cfg
    if not cfg.demo_mode or (ctx is not None and not ctx.get("demo_hint", True)):
        return ""
    t = auth.t
    if pin:
        line, js = t("demo.pin", pin=cfg.demo_pin), ""
    else:
        line = t("demo.creds", user=_fill("demo", cfg.demo_password),
                 admin=_fill("demoadmin", cfg.demo_password), pw=_e(cfg.demo_password))
        js = _DEMO_JS
    return (f"<div class=demobar><b>{_e(t('demo.title'))}</b><br>{line}"
            f"<div class=demowarn>{t('demo.warn')}</div></div>{js}")


def _cf(ctx) -> str:
    """Hidden CSRF field for forms (empty if CSRF is off → ctx without 'csrf')."""
    return f"<input type=hidden name=_csrf value='{_e(ctx.get('csrf', ''))}'>"


def _csrf_js(auth) -> str:
    """JS helper: reads the CSRF cookie → tsCsrf(); the fetch calls send X-CSRF-Token."""
    return ("<script>function tsCsrf(){return (document.cookie.match("
            f"/(?:^|; ){_e(auth.csrf_cookie_name)}=([^;]+)/)||[])[1]||''}}</script>")


# ---------- Default renderers  (fn(auth, ctx) -> str) ----------

def _login(auth, ctx) -> str:
    """ctx: next, error, warn (optional). Shows all active login methods."""
    cfg = auth.cfg
    t = auth.t
    next_ = ctx.get("next", "/")
    error = ctx.get("error", "")
    methods = cfg.enabled_methods()
    # Messages (PO 2026-10-08): notice ("You have been signed out"), warning and error of a sign-in attempt stand
    # together in a separate box below the card, each with an icon — no longer scattered in the card.
    messages = _messages([("info", ctx.get("info")), ("warn", ctx.get("warn")), ("error", error)])
    _or = f"<div class=or>{_e(t('or'))}</div>"
    remember = ""
    if cfg.remember_me_enabled:
        remember = ("<label class=remember><input type=checkbox name=remember value=1 checked> "
                    f"{_e(t('login.remember'))}</label>")
    id_label, id_ac = _ident(auth)
    # In demo mode the browser would otherwise fill in a saved password and the login fails.
    pw_ac = "new-password" if cfg.demo_mode else "current-password"
    pw = ""
    if "password" in methods:
        pw = (f"<form method=post action='__TS_P__{_e(cfg.login_path)}'>"
              f"<input type=hidden name=next value='{_e(next_)}'>{_cf(ctx)}"
              f"<label>{_e(id_label)}</label><input name=username required autofocus autocomplete={id_ac} autocapitalize=none autocorrect=off spellcheck=false>"
              f"<label>{_e(t('login.password'))}</label><input name=password required type=password autocomplete={pw_ac}>"
              f"{remember}"
              f"<button type=submit>{_e(t('login.submit'))}</button></form>")
    pin = ""
    if "pin" in methods:
        pin = (f"{_or if pw else ''}<form method=post action='__TS_P__/auth/pin'>"
               f"<input type=hidden name=next value='{_e(next_)}'>{_cf(ctx)}"
               f"<label>{_e(id_label)}</label><input name=username autocomplete={id_ac} autocapitalize=none autocorrect=off spellcheck=false{'' if pw else ' autofocus'}>"
               f"<label>{_e(t('login.pin'))}</label><input name=pin required type=password inputmode=numeric autocomplete=off class=code>"
               f"{remember}"
               f"<button type=submit>{_e(t('login.pin_submit'))}</button></form>")
    magic = ""
    # Only with the self-request (T-33): with `magiclink_self_request=False` the route is gone and
    # links come from the admin — a button to a 404 would be a dead end.
    if "magic" in methods and getattr(cfg, "magiclink_self_request", True):
        magic = f"<a class=btn2 href='__TS_P__/auth/magic/request?next={_next_q(next_)}{_e(_app_q(ctx, "&"))}'>{_e(t('login.magic'))}</a>"
    # `app` (T-14) travels along: without it the button would start the round with the default client,
    # and the approval for THIS application would never come about (B-2).
    app_q = f"&app={_e(_quote(ctx['app']))}" if ctx.get("app") else ""
    oidc = (f"<a class=btn2 href='__TS_P__/auth/oidc/start?next={_next_q(next_)}{app_q}'>{_e(cfg.oidc_name)}</a>"
            if "oidc" in methods else "")
    saml = (f"<a class=btn2 href='__TS_P__/auth/saml/login?next={_next_q(next_)}'>{_e(cfg.saml_name)}</a>"
            if "saml" in methods else "")
    passkey = f"<button class=btn2 type=button id=pkbtn>{_e(t('login.passkey'))}</button>" if "passkey" in methods else ""
    # Cross-device sign-in (T-33): a POST, the request comes into being only with this click.
    qr = (f"<form method=post action='__TS_P__/auth/qr/start' class=qrstart>"
          f"<input type=hidden name=next value='{_e(next_)}'>{_cf(ctx)}"
          f"<button type=submit class=btn2>{_e(t('login.qr'))}</button></form>"
          if getattr(cfg, "qr_login_enabled", False) else "")
    others = oidc + saml + passkey + magic + qr
    sep = _or if others and (pw or pin) else ""
    links = []
    if cfg.allow_signup:
        links.append(f"<a href='__TS_P__/auth/register?next={_next_q(next_)}'>{_e(t('login.signup'))}</a>")
    if getattr(cfg, "password_reset_enabled", False) and cfg.magiclink_enabled:
        links.append(f"<a href='__TS_P__/auth/forgot{_e(_app_q(ctx))}'>{_e(t('login.forgot'))}</a>")
    signup = f"<div class=hint>{' · '.join(links)}</div>" if links else ""
    js = (_csrf_js(auth) + _dialog.assets(auth) + _PASSKEY_LOGIN_JS.replace("__NEXT__", _next_q(next_))
          .replace("__PK_FAILED__", json.dumps(t("login.passkey_failed")))
          .replace("__PK_ABORTED__", json.dumps(t("login.passkey_aborted")))) if "passkey" in methods else ""
    # In front of an application (forward_apps[host].name, T-21) the page says what you sign in for. With a brand
    # (gate_brand) the brand stands on top and the application as its own line below.
    brand = getattr(cfg, "gate_brand", "") or ""
    # In an app frame (T-91) the page names that application even when only `?app=` chose it — with its icon (T-104,
    # ADR-19: "Sign in to <application>" and the application's icon, like a provider's hosted sign-in).
    if not ctx.get("app_name") and ctx.get("frame"):
        ctx = {**ctx, "app_name": ctx["frame"]["name"], "app_icon": ctx["frame"].get("icon")}
    icon = _topbar.app_icon(ctx.get("app_icon"), 48, "app-icon") if ctx.get("app_name") else ""
    if brand:
        title = t("login.for_app", name=brand)
    else:
        title = t("login.for_app", name=ctx["app_name"]) if ctx.get("app_name") else cfg.rp_name
    app_line = (f"<p class=app>{_e(t('login.app_line', name=ctx['app_name']))}</p>"
                 if brand and ctx.get("app_name") else "")
    # Signed out of this application only (T-22): back in with one click, without a new sign-in.
    further = ""
    if ctx.get("resume_user"):
        gh = f"<input type=hidden name=gate_host value='{_e(ctx['gate_host'])}'>" if ctx.get("gate_host") else ""
        further = (f"<form method=post action='__TS_P__/auth/gate/resume'>"
                  f"<input type=hidden name=next value='{_e(next_)}'>{gh}{_cf(ctx)}"
                  f"<button type=submit>{_e(t('gate.resume', name=ctx['resume_user']))}</button></form>"
                  + (_or if (pw or pin or others) else ""))
    body = f"{icon}<h1>{_e(title)}</h1>{app_line}{further}{pw}{pin}{sep}{others}{signup}{js}"
    page_title = t("login.brand_title", name=brand) if brand else t("login.submit")
    return _page(auth, page_title, body, top=_demobar(auth, ctx=ctx), below=messages, ctx=ctx)


def _totp(auth, ctx) -> str:
    """ctx: next, error."""
    t = auth.t
    messages = _messages([("error", ctx.get("error"))])
    body = (f"<h1>{_e(t('totp.title'))}</h1>"
            f"<form method=post action='__TS_P__/auth/totp'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"<label>{_e(t('totp.label'))}</label>"
            f"<input name=code class=code inputmode=numeric autocomplete=one-time-code autofocus maxlength=6>"
            f"<button type=submit>{_e(t('totp.submit'))}</button></form>"
            f"<div class=hint><a href='__TS_P__/auth/logout'>{_e(t('cancel'))}</a></div>")
    return _page(auth, t("totp.title"), body, below=messages, ctx=ctx)


def _account(auth, ctx) -> str:
    """ctx: user, methods, has_totp, has_pin, password_initial, password_directory, is_admin, admin_panel, admin_path, events. Self-service + logout.
    Fully replaceable via auth.set_template('account', fn)."""
    u = ctx["user"]
    t = auth.t
    methods = ctx.get("methods", [])
    name = _e(u["display_name"] or u["username"])
    sections = []

    # Change username and address yourself (PO decision 2026-09-25) — fresh step-up; the
    # address only counts after the confirmation link sent to it.
    if ctx.get("username_change"):
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.username'))}</h2>"
            f"<input id=un_new autocomplete=username value='{_e(u['username'])}'>"
            f"<button data-act=setname>{_e(t('acc.username_change'))}</button><span id=un_msg class=msg></span></div>")
    if ctx.get("email_change"):
        current = u.get("email") or ""
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.email'))}</h2>"
            + (f"<div class=msg>{_e(current)}</div>" if current else "")
            + f"<input id=mail_new type=email autocomplete=email placeholder='{_e(t('acc.email_new'))}'>"
            f"<button data-act=setmail>{_e(t('acc.email_change'))}</button><span id=mail_msg class=msg></span></div>")

    # Set password (B-10): an account without one has no current password to type — the
    # server asks for a fresh sign-in or step-up instead (`set_initial_password`).
    if "password" in methods and ctx.get("password_initial"):
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.password'))}</h2>"
            f"<p class='msg evhint'>{_e(t('acc.pw_none'))}</p>"
            f"<input id=pw_new type=password autocomplete=new-password placeholder='{_e(t('acc.pw_new'))}'>"
            f"<button data-act=setpw>{_e(t('acc.pw_set'))}</button><span id=pw_msg class=msg></span></div>")
    # The password lives in the directory (LDAP account without a local one): nothing to change here.
    elif "password" in methods and ctx.get("password_directory"):
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.password'))}</h2>"
            f"<p class='msg evhint'>{_e(t('acc.pw_directory'))}</p></div>")
    # Change password
    elif "password" in methods:
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.password'))}</h2>"
            f"<input id=pw_cur type=password placeholder='{_e(t('acc.pw_cur'))}'>"
            f"<input id=pw_new type=password placeholder='{_e(t('acc.pw_new'))}'>"
            f"<button data-act=changepw>{_e(t('acc.pw_change'))}</button><span id=pw_msg class=msg></span></div>")

    # PIN
    if "pin" in methods:
        state = t("acc.pin_set_state") if ctx.get("has_pin") else t("acc.pin_unset_state")
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.pin'))} <small>({_e(state)})</small></h2>"
            f"<input id=pin_new type=password inputmode=numeric placeholder='{_e(t('acc.pin_new'))}'>"
            f"<button data-act=setpin>{_e(t('acc.pin_set'))}</button> "
            f"<button class=warn data-act=delpin>{_e(t('acc.pin_remove'))}</button><span id=pin_msg class=msg></span></div>")

    # TOTP / 2FA
    if auth.cfg.totp_enabled:
        if ctx.get("has_totp"):
            # How many one-time codes remain, the page says on its own (B2-7): a
            # used code was not tracked anywhere until T-13, and whoever used up the last one
            # only learned of it when they needed it.
            # B-9b: its own line below the buttons — inline it wrapped across two lines at 1280 px
            # and ran into the button row. "None" is told apart from "only n left" (B-9a).
            rest = ctx.get("recovery_left")
            notice = ""
            if rest is not None:
                tight = rest <= ctx.get("recovery_warn", 3)
                key = "acc.recovery_none" if rest == 0 else ("acc.recovery_low" if tight else "acc.recovery_left")
                notice = (f"<div id=rc_left class='rcleft {'err' if tight else 'ok'}'>"
                          f"{_e(t(key, n=rest))}</div>")
            # T-94: with `recovery_codes_enabled=False` no code action (the route answers 404 anyway).
            codes = (f" <button data-act=recovery>{_e(t('acc.recovery'))}</button>"
                     if getattr(auth.cfg, "recovery_codes_enabled", True) else "")
            totp = (f"<span class=ok>{_e(t('acc.totp_active'))}</span> "
                    f"<button class=warn data-act=deltotp>{_e(t('acc.totp_off'))}</button>{codes}")
        else:
            notice = ""
            totp = (f"<a class=btnlink href='__TS_P__/auth/totp/setup{_e(_app_q(ctx))}'>"
                    f"{_e(t('acc.totp_setup'))}</a>")
        sections.append(f"<div class=sec><h2 id=totp>{_e(t('acc.totp'))}</h2>{totp}<span id=totp_msg class=msg></span>"
                        f"{notice}</div>")

    # T-99: link with the OIDC provider — a plain POST with the CSRF token (never a GET or a script call), a fresh
    # confirmation here and an active sign-in there; the identity belongs to this account afterwards.
    if ctx.get("oidc_link"):
        sections.append(
            f"<div class=sec><h2 id=link>{_e(t('acc.oidc_link_title', name=auth.cfg.oidc_name))}</h2>"
            f"<p class='msg evhint'>{_e(t('acc.oidc_link_hint', name=auth.cfg.oidc_name))}</p>"
            f"<form method=post action='__TS_P__/auth/oidc/link'>{_cf(ctx)}"
            f"<button type=submit>{_e(t('acc.oidc_link', name=auth.cfg.oidc_name))}</button></form></div>")
    sections.extend(_identity_sections(auth, ctx))

    # Passkeys
    if "passkey" in methods:
        sections.append(
            f"<div class=sec><h2 id=passkeys>{_e(t('acc.passkeys'))}</h2><ul id=pklist></ul>"
            f"<button data-act=addpk>{_e(t('acc.passkey_add'))}</button><span id=pk_msg class=msg></span></div>")

    # API keys
    if auth.cfg.apikey_enabled:
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.keys'))}</h2><ul id=keylist></ul>"
            f"<input id=key_name placeholder='{_e(t('acc.key_name'))}'>"
            f"<button data-act=mkkey>{_e(t('acc.key_create'))}</button><span id=key_msg class=msg></span></div>")

    # App passwords (T-66): for clients without a browser at the gate — only when an application takes them.
    sections.append(_app_passwords_section(auth, ctx, u))

    # Active sessions (always)
    sections.append(
        f"<div class=sec><h2 id=sessions>{_e(t('acc.sessions'))}</h2><ul id=sesslist></ul>"
        f"<button class=warn data-act=revokeothers>{_e(t('acc.sessions_revoke'))}</button>"
        "<span id=sess_msg class=msg></span></div>")

    # Connected programs (OAuth, T-36) and services (T-60)
    sections.append(_devices_section(auth, ctx))
    sections.append(_pairing_section(auth, ctx))
    sections.append(_services_section(auth, ctx))

    # Own events (H-7): whoever sees that a sign-in happened at 3 a.m. from a foreign address
    # speaks up — the log so far lay only with the operator. Rendered
    # server-side (no further endpoint), time as UTC, because the page does not know the
    # reader's zone. `events` missing in the ctx of a custom template/preview → section omitted.
    # The spacing comes from a class in the page `<style>`, not from `style=`: the strict CSP
    # allows styles only via nonce, and that does not apply to attributes (integration finding 9).
    events = ctx.get("events")
    if events is not None:
        import datetime as _dt
        lines = "".join(
            f"<li><code>{_e(_dt.datetime.fromtimestamp(int(ev['ts']), _dt.timezone.utc).strftime('%Y-%m-%d %H:%M'))}"
            f" UTC</code> {_e(ev['event'])} <small>"
            f"{_e(t('acc.events_by_admin') if ev.get('by_admin') else (ev.get('ip') or ''))}</small></li>"
            for ev in events) or f"<li>{_e(t('acc.events_none'))}</li>"
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.events'))}</h2>"
            f"<p class='msg evhint'>{_e(t('acc.events_hint'))}</p>"
            f"<ul id=eventlist>{lines}</ul></div>")

    admin_link = (f"<a href='{_e('__TS_P__' + ctx.get('admin_path', '/auth/admin'))}'>{_e(t('acc.admin'))}</a>"
                  if ctx.get("admin_panel", ctx.get("is_admin")) else "")

    css = """
    .tsmain{max-width:640px;margin:0 auto;padding:24px;display:block}
    .tsmain header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
    .tsmain header h1{font-size:20px;margin:0}
    .tsmain .sec{background:var(--ts-surface);border:1px solid var(--ts-line);
         border-radius:var(--ts-radius);padding:16px;margin-bottom:14px}
    .tsmain .sec h2{font-size:13px;color:var(--ts-muted);text-transform:uppercase;
         letter-spacing:.05em;margin:0 0 12px;scroll-margin-top:72px}
    .tsmain .sec small{text-transform:none;letter-spacing:0}
    .tsmain .sec input{margin:4px 0}
    .tsmain .sec button,.tsmain .btnlink{width:auto;display:inline-block;margin:8px 6px 0 0;padding:9px 14px}
    .tsmain button.warn{background:var(--ts-danger);color:var(--ts-danger-ink)}
    .tsmain .btnlink{background:var(--ts-neutral);color:var(--ts-neutral-ink);border-radius:8px;
         text-decoration:none;padding:9px 14px}
    .tsmain .msg{margin-left:8px;font-size:12px;color:var(--ts-muted)}
    .tsmain .msg.evhint{margin:0 0 8px}
    .tsmain .msg.good,.tsmain .ok{color:var(--ts-ok-ink);background:none;padding:0}
    .tsmain .msg.bad,.tsmain .bad{color:var(--ts-err-ink)}
    .tsmain ul{list-style:none;padding:0;margin:0 0 8px}
    .tsmain li{padding:4px 0;font-size:13px;border-bottom:1px solid var(--ts-line-soft)}
    .tsmain a{color:var(--ts-link)}
    .tsmain .rcleft{display:block;margin:12px 0 0;font-size:13px}
    .tsmain form.devrevoke{margin:0}
    .tsmain fieldset.apapps{border:0;padding:0;margin:8px 0}
    .tsmain fieldset.apapps legend{font-size:12px;color:var(--ts-muted);padding:0;margin-bottom:2px}
    .tsmain label.apapp{display:flex;gap:8px;align-items:center;min-height:36px;font-size:14px}
    .tsmain label.apapp input{width:auto;margin:0}
    .tsmain label.apdays{display:flex;gap:8px;align-items:center;font-size:13px;margin:4px 0}
    .tsmain label.apdays select{width:auto;min-height:44px;background:var(--ts-field-bg);color:var(--ts-ink);
         border:1px solid var(--ts-field-line);border-radius:8px;padding:8px 10px;font-size:14px}
    """
    # `static=True`: only show the page, fetch nothing (preview/screenshot).
    static = bool(ctx.get("static"))
    pkjs = "" if static else (_PASSKEY_REGISTER_JS if "passkey" in methods else "")
    # Admin panel and sign-out live in the top bar's account menu (T-64); only without the bar
    # (`topbar_enabled=False`) the page carries the two links itself.
    own_links = ("" if getattr(auth.cfg, "topbar_enabled", True) else
                 f"<div>{admin_link} <a href='__TS_P__/auth/logout'>{_e(t('logout'))}</a></div>")
    body = (f"<header><h1>{_e(t('acc.title'))} · {name}</h1>{own_links}</header>"
            + "".join(sections)
            + ("" if static else _dialog.assets(auth) + _ACCOUNT_JS.replace("__CSRFCK__", _e(auth.csrf_cookie_name)).replace("__TXT__", _account_texts(auth))
               + _revoke_js(auth, "location.pathname+'?revoke_others=1" + _app_q(ctx, "&") + "'") + _ACCOUNT_RETURN_JS
               .replace("__CONFIRM__", json.dumps(t("acc.sessions_confirm"))))
            + pkjs)
    # Account uses full width (no card) + account CSS + branding
    return _page(auth, t("acc.title"), f"<style>{css}</style>{body}", card=False, ctx=ctx, current="account")


#: Texts of the account page's JavaScript (no keys in `messages.py` yet — they are chosen by
#: `config.lang`, fallback "en"; the "de" column is the earlier German wording).
_ACCOUNT_TEXT = {
    "en": {
        "locale": "en-GB", "error": "Error", "mail_sent": "Link sent — please confirm it in the new mailbox",
        "changed": "✓ changed", "set": "✓ set", "removed": "✓ removed",
        "confirm_2fa_off": "Really disable 2FA?",
        "confirm_recovery": "Generate new recovery codes? The old ones become invalid.",
        "recovery_title": "New recovery codes",
        "recovery_note": "Write these down safely now — they are shown only once.",
        "revoked": "(revoked)", "revoke": "revoke", "none": "none", "delete": "delete", "this": "(this one)",
        "key_title": "New API key", "key_note": "Copy it now — it is not shown again.", "confirm_end_others": "End all other sessions?",
        "ended": "✓ ended", "added": "✓ added", "failed": "failed", "aborted": "aborted: ",
        "ap_title": "New app password", "ap_note": "Copy it now — it is not shown again. Sign in with the user name "
        "“__USER__” and this password; it works only for the applications you chose.",
        "ap_created": "created", "ap_last": "last used", "ap_unused": "not used yet", "ap_expires": "expires",
        "ap_no_expiry": "no expiry", "ap_expired": "(expired)", "ap_confirm": "Revoke this app password? Devices "
        "that use it are signed out at once.", "ap_pick": "Choose at least one application.",
        "sv_title": "Pairing code", "sv_note": "Shown only now, valid for a few minutes and only once. On the service:",
        "sv_last": "last token", "sv_unused": "no token yet", "sv_key_expires": "key expires",
        "sv_key_expired": "(key expired)", "sv_confirm": "Revoke this service? Its key is deleted, its access ends "
        "at once.", "sv_pick": "Choose at least one application.",
        "pc_title": "Pairing code", "pc_note": "Enter it in the setup script now. It works once and for __MIN__ "
        "minutes; never pass it on.",
    },
    "de": {
        "locale": "de-DE", "error": "Fehler", "mail_sent": "Link verschickt — bitte in der neuen Adresse bestätigen",
        "changed": "✓ geändert", "set": "✓ gesetzt", "removed": "✓ entfernt",
        "confirm_2fa_off": "2FA wirklich deaktivieren?",
        "confirm_recovery": "Neue Recovery-Codes erzeugen? Alte werden ungültig.",
        "recovery_title": "Neue Recovery-Codes",
        "recovery_note": "Jetzt sicher notieren — sie werden nur einmal angezeigt.",
        "revoked": "(widerrufen)", "revoke": "widerrufen", "none": "keine", "delete": "löschen", "this": "(diese)",
        "key_title": "Neuer API-Key", "key_note": "Jetzt kopieren — er wird nicht erneut angezeigt.", "confirm_end_others": "Alle anderen Sitzungen beenden?",
        "ended": "✓ beendet", "added": "✓ hinzugefügt", "failed": "fehlgeschlagen", "aborted": "abgebrochen: ",
        "ap_title": "Neues App-Passwort", "ap_note": "Jetzt kopieren — es wird nicht erneut angezeigt. Anmelden mit "
        "dem Benutzernamen „__USER__“ und diesem Passwort; es gilt nur für die gewählten Anwendungen.",
        "ap_created": "erstellt", "ap_last": "zuletzt genutzt", "ap_unused": "noch nicht genutzt",
        "ap_expires": "läuft ab", "ap_no_expiry": "ohne Ablauf", "ap_expired": "(abgelaufen)",
        "ap_confirm": "Dieses App-Passwort widerrufen? Geräte, die es nutzen, werden sofort abgemeldet.",
        "ap_pick": "Mindestens eine Anwendung wählen.",
        "sv_title": "Kopplungscode", "sv_note": "Wird nur jetzt angezeigt, gilt wenige Minuten und nur einmal. Auf dem "
        "Dienst:", "sv_last": "letztes Token", "sv_unused": "noch kein Token", "sv_key_expires": "Schlüssel läuft ab",
        "sv_key_expired": "(Schlüssel abgelaufen)", "sv_confirm": "Diesen Dienst widerrufen? Sein Schlüssel wird "
        "gelöscht, sein Zugriff endet sofort.", "sv_pick": "Mindestens eine Anwendung wählen.",
        "pc_title": "Kopplungscode", "pc_note": "Jetzt im Einrichtungsskript eingeben. Er gilt einmal und __MIN__ "
        "Minuten; nie weitergeben.",
    },
}


def _account_texts(auth) -> str:
    """The account page's JS texts as a JSON literal (ASCII-escaped, so it is safe inside `<script>`)."""
    texts: dict = dict(_ACCOUNT_TEXT.get(auth.cfg.lang) or _ACCOUNT_TEXT["en"])
    # The remainder after "generate" (B-9b): the same wording as the server-rendered line; `__N__`
    # is replaced in the browser.
    texts.update(rc_left=auth.t("acc.recovery_left", n="__N__"), rc_low=auth.t("acc.recovery_low", n="__N__"),
                 rc_warn=getattr(auth, "_RECOVERY_WARN_THRESHOLD", 3))
    return json.dumps(texts)


_ACCOUNT_JS = """
<script>
function tsCsrf(){return (document.cookie.match(/(?:^|; )__CSRFCK__=([^;]+)/)||[])[1]||''}
const TXT=__TXT__;
async function J(u,b){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},body:JSON.stringify(b||{})});
  // 403 + X-TinySesam-Reauth: factor management has required a fresh confirmation since R3-3.
  // Without this switch the button failed silently once the freshness had expired.
  const re=r.headers.get('X-TinySesam-Reauth');
  if(r.status===403&&re){location.href=re+'?next='+encodeURIComponent(location.pathname+location.search);return r}
  return r}
const say=(id,t,good)=>{const e=document.getElementById(id);if(e){e.textContent=t;e.className='msg '+(good?'good':'bad')}};
async function setname(){const r=await J('__TS_P__/auth/account/username',{username:un_new.value});
  const j=await r.json().catch(()=>({}));say('un_msg',r.ok?'✓':(j.detail||TXT.error),r.ok)}
async function setmail(){const r=await J('__TS_P__/auth/account/email',{email:mail_new.value});
  const j=await r.json().catch(()=>({}));say('mail_msg',r.ok?'✓ '+TXT.mail_sent:(j.detail||TXT.error),r.ok);if(r.ok)mail_new.value=''}
async function changepw(){const r=await J('__TS_P__/auth/password',{current:pw_cur.value,new:pw_new.value});
  say('pw_msg',r.ok?TXT.changed:(await r.json()).detail||TXT.error,r.ok);if(r.ok){pw_cur.value='';pw_new.value=''}}
// B-10: the first password — no current one; the reload then shows the regular change form.
async function setpw(){const r=await J('__TS_P__/auth/password/set',{new:pw_new.value});await offer(r);
  say('pw_msg',r.ok?TXT.set:(await r.json().catch(()=>({}))).detail||TXT.error,r.ok);
  if(r.ok){pw_new.value='';setTimeout(()=>location.reload(),600)}}
async function setpin(){const r=await J('__TS_P__/auth/pin/set',{pin:pin_new.value});await offer(r);
  say('pin_msg',r.ok?TXT.set:(await r.json()).detail||TXT.error,r.ok);if(r.ok)setTimeout(()=>location.reload(),600)}
// Check first, then report: both buttons used to say "done" UNCONDITIONALLY and reload —
// even on 403 (expired step-up freshness, missing CSRF token) or 500. The user saw
// "removed", the factor was still there.
async function delpin(){const r=await J('__TS_P__/auth/pin/disable');await offer(r);
  say('pin_msg',r.ok?TXT.removed:(await r.json().catch(()=>({}))).detail||TXT.error,r.ok);
  if(r.ok)setTimeout(()=>location.reload(),600)}
async function deltotp(){if(!await tsConfirm(TXT.confirm_2fa_off,{danger:true}))return;
  const r=await J('__TS_P__/auth/totp/disable');await offer(r);
  if(r.ok)location.reload();else say('totp_msg',(await r.json().catch(()=>({}))).detail||TXT.error,false)}
async function recovery(){if(!await tsConfirm(TXT.confirm_recovery))return;
  const r=await (await J('__TS_P__/auth/totp/recovery')).json();
  if(r.codes){
    // B-9b: the remainder line still said the old number.
    const b=document.getElementById('rc_left'),n=r.codes.length,low=n<=TXT.rc_warn;
    if(b){b.textContent=(low?TXT.rc_low:TXT.rc_left).replace('__N__',n);b.className='rcleft '+(low?'err':'ok')}
    // Shown once, in the dialog with its copy button (T-35) — not left standing on the page.
    await tsSecret(TXT.recovery_title,r.codes.join('\\n'),TXT.recovery_note)}
  else say('totp_msg',r.detail||TXT.error,false)}
async function loadkeys(){const el=document.getElementById('keylist');if(!el)return;
  const ks=await (await fetch('__TS_P__/auth/apikeys')).json().catch(()=>[]);
  if(!Array.isArray(ks)){el.innerHTML='<li>—</li>';return}
  el.innerHTML=ks.map(k=>`<li>${esc0(k.prefix)} ${esc0(k.name)} ${k.revoked?'<span class=bad>'+TXT.revoked+'</span>':`<button class=warn data-act=revk data-id="${esc0(k.id)}">${TXT.revoke}</button>`}</li>`).join('')||'<li>'+TXT.none+'</li>'}
async function mkkey(){const r=await (await J('__TS_P__/auth/apikeys',{name:key_name.value})).json().catch(()=>({}));
  loadkeys();
  if(r.key){key_name.value='';await tsSecret(TXT.key_title,r.key,TXT.key_note)}
  else say('key_msg',r.detail||TXT.error,false)}
async function revk(id){await J('__TS_P__/auth/apikeys/'+id+'/revoke');loadkeys()}
// App passwords (T-66): created once, shown once in the dialog with its copy button, then only by name.
const dt0=t=>new Date(t*1000).toLocaleString(TXT.locale);
async function loadap(){const el=document.getElementById('aplist');if(!el)return;
  const ps=await (await fetch('__TS_P__/auth/app-passwords')).json().catch(()=>[]);
  if(!Array.isArray(ps)){el.innerHTML='<li>—</li>';return}
  el.innerHTML=ps.map(p=>`<li><b>${esc0(p.name)}</b> · ${esc0((p.hosts||[]).join(', '))}<br><small class=msg>${TXT.ap_created} ${dt0(p.created_at)} · ${p.last_used?TXT.ap_last+' '+dt0(p.last_used)+' · '+esc0(p.last_ip||'?'):TXT.ap_unused} · ${p.expires_at?TXT.ap_expires+' '+dt0(p.expires_at):TXT.ap_no_expiry}</small> ${p.revoked?'<span class=bad>'+TXT.revoked+'</span>':(p.expired?'<span class=bad>'+TXT.ap_expired+'</span>':`<button class=warn data-act=revap data-id="${esc0(p.id)}">${TXT.revoke}</button>`)}</li>`).join('')||'<li>'+TXT.none+'</li>'}
async function mkap(){const hosts=[...document.querySelectorAll('input[name=ap_host]:checked')].map(c=>c.value);
  if(!hosts.length){say('ap_msg',TXT.ap_pick,false);return}
  const r=await J('__TS_P__/auth/app-passwords',{name:ap_name.value,hosts,expires_days:parseInt(ap_days.value,10)});
  const j=await r.json().catch(()=>({}));loadap();
  if(j.secret){ap_name.value='';say('ap_msg','',true);
    await tsSecret(TXT.ap_title,j.secret,TXT.ap_note.replace('__USER__',document.getElementById('apsec').dataset.user))}
  else if(!(r.status===403&&r.headers.get('X-TinySesam-Reauth')))say('ap_msg',j.detail||TXT.error,false)}
async function revap(id){if(!await tsConfirm(TXT.ap_confirm,{danger:true}))return;
  await J('__TS_P__/auth/app-passwords/'+id+'/revoke');loadap()}
// Services (T-60): a pairing code is shown once; the service redeems it and keeps its key itself.
async function loadsv(){const el=document.getElementById('svlist');if(!el)return;
  const ss=await (await fetch('__TS_P__/auth/oauth/services')).json().catch(()=>[]);
  if(!Array.isArray(ss)){el.innerHTML='<li>—</li>';return}
  el.innerHTML=ss.map(s=>{const k=(s.keys||[]).find(x=>x.valid);return `<li><b>${esc0(s.name)}</b> <small><code>${esc0(s.client_id)}</code></small> · ${esc0((s.resources||[]).join(', '))}<br><small class=msg>${TXT.ap_created} ${dt0(s.created_at)} · ${s.last_used?TXT.sv_last+' '+dt0(s.last_used)+' · '+esc0(s.last_ip||'?'):TXT.sv_unused} · ${k?(k.expires_at?TXT.sv_key_expires+' '+dt0(k.expires_at):TXT.ap_no_expiry):TXT.sv_key_expired}</small> <button class=warn data-act=revsv data-id="${esc0(s.client_id)}">${TXT.revoke}</button></li>`}).join('')||'<li>'+TXT.none+'</li>'}
async function mksv(){const resources=[...document.querySelectorAll('input[name=sv_res]:checked')].map(c=>c.value);
  if(!resources.length){say('sv_msg',TXT.sv_pick,false);return}
  const r=await J('__TS_P__/auth/oauth/services/pairing',{name:sv_name.value,resources});
  const j=await r.json().catch(()=>({}));
  if(j.code){sv_name.value='';say('sv_msg','',true);await tsSecret(TXT.sv_title,j.code,TXT.sv_note+'\\ntinysesam-client pair '+j.issuer+' '+j.code);loadsv()}
  else if(!(r.status===403&&r.headers.get('X-TinySesam-Reauth')))say('sv_msg',j.detail||TXT.error,false)}
// Pairing code for a program (ADR-14): shown once; the setup script redeems it right before the program signs in.
async function mkpc(){const sel=document.getElementById('pc_res');
  const r=await J('__TS_P__/auth/oauth/pairing',sel&&sel.value?{resource:sel.value}:{});
  const j=await r.json().catch(()=>({}));
  if(j.code){say('pc_msg','',true);await tsSecret(TXT.pc_title,j.code,TXT.pc_note.replace('__MIN__',
    document.getElementById('pcsec').dataset.minutes))}
  else if(!(r.status===403&&r.headers.get('X-TinySesam-Reauth')))say('pc_msg',j.detail||TXT.error,false)}
async function revsv(id){if(!await tsConfirm(TXT.sv_confirm,{danger:true}))return;
  await J('__TS_P__/auth/oauth/services/'+encodeURIComponent(id)+'/revoke');loadsv()}
async function loadpk(){const el=document.getElementById('pklist');if(!el)return;
  const ps=await (await fetch('__TS_P__/auth/passkey/list')).json();
  el.innerHTML=ps.map(p=>`<li>${esc0(p.name||'Passkey')} <button class=warn data-act=delpk data-id="${esc0(p.id)}">${TXT.delete}</button></li>`).join('')||'<li>'+TXT.none+'</li>'}
async function delpk(id){await offer(await J('__TS_P__/auth/passkey/delete',{id}));loadpk()}
async function loadsess(){const el=document.getElementById('sesslist');if(!el)return;
  const ss=await (await fetch('__TS_P__/auth/sessions')).json().catch(()=>[]);
  if(!Array.isArray(ss)){el.innerHTML='<li>—</li>';return}
  el.innerHTML=ss.map(s=>`<li>${new Date(s.created_at*1000).toLocaleString(TXT.locale)} · ${esc0(s.method)} · ${esc0(s.ip)||'?'} ${s.current?'<b>'+TXT.this+'</b>':''}<br><small class=msg>${esc0(s.user_agent)}</small></li>`).join('')||'<li>'+TXT.none+'</li>'}
// Every value from the API goes through esc0 before it lands in innerHTML (R8-6): key and
// passkey names are set by the user, and up to 0.19.0 they stood raw in the markup — a name
// like <img src=x onerror=…> ran as code. All five characters, because values also appear in attributes.
function esc0(s){return (s??'').toString().replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function revokeothers(){if(!await tsConfirm(TXT.confirm_end_others,{danger:true}))return;
  if(await tsRevokeOthers())say('sess_msg',TXT.ended,true);loadsess()}
// One delegated listener instead of inline click handlers — otherwise the strict CSP
// blocks the buttons. The buttons loaded later via JS (data-act=revk/delpk) are reached as well.
document.addEventListener('click',function(e){var b=e.target.closest('[data-act]');if(!b)return;
  var f=window[b.dataset.act];if(typeof f==='function'){e.preventDefault();f(b.dataset.id)}});
loadkeys();loadap();loadsv();loadpk();loadsess();
</script>
"""

_PASSKEY_REGISTER_JS = """
<script>
async function addpk(){
  try{
    // B-12: a new passkey wants a fresh confirmation — J() follows X-TinySesam-Reauth to the reauth page.
    const rb=await J('__TS_P__/auth/passkey/register/begin');if(!rb.ok){say('pk_msg',(await rb.json().catch(()=>({}))).detail||TXT.failed,false);return}
    const o=await rb.json();
    o.challenge=Uint8Array.from(atob(o.challenge.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    o.user.id=Uint8Array.from(atob(o.user.id.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    (o.excludeCredentials||[]).forEach(c=>c.id=Uint8Array.from(atob(c.id.replace(/-/g,'+').replace(/_/g,'/')),x=>x.charCodeAt(0)));
    const cred=await navigator.credentials.create({publicKey:o});
    const enc=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    const payload={id:cred.id,rawId:enc(cred.rawId),type:cred.type,response:{
      clientDataJSON:enc(cred.response.clientDataJSON),attestationObject:enc(cred.response.attestationObject),
      transports:(cred.response.getTransports&&cred.response.getTransports())||[]}};
    const r=await fetch('__TS_P__/auth/passkey/register/finish',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},body:JSON.stringify(payload)});
    // T-56: a refused registration (no user verification) says why instead of a bare "failed".
    say('pk_msg',r.ok?TXT.added:((await r.clone().json().catch(()=>({}))).detail||TXT.failed),r.ok);loadpk();await offer(r);loadsess();
  }catch(e){say('pk_msg',TXT.aborted+e,false)}
}
</script>
"""


def _register(auth, ctx) -> str:
    """ctx: next, invite, email, error, invite_only, sent_verify (optional)."""
    t = auth.t
    if ctx.get("sent_verify"):
        body = (f"<h1>{_e(t('reg.verify_title'))}</h1>"
                f"<div class=hint>{_e(t('reg.verify_hint'))}</div>"
                f"<a class=btn2 href='__TS_P__/auth/login'>{_e(t('magic.to_login'))}</a>")
        return _page(auth, t("reg.verify_title"), body, below=_messages([("ok", t("reg.verify"))]), ctx=ctx)
    cfg = auth.cfg
    messages = _messages([("error", ctx.get("error"))])
    emailro = " readonly" if ctx.get("invite") and ctx.get("email") else ""
    # The fields follow the config: in e-mail mode the address is the identifier; an optional
    # e-mail field appears only if the app does anything with it at all (login link,
    # forgot password, confirmation). Otherwise you ask for data you never use.
    email_mode = cfg.login_identifier == "email"
    email_used = (cfg.signup_require_email or email_mode or cfg.magiclink_enabled
                  or getattr(cfg, "password_reset_enabled", False) or cfg.signup_verify_email)
    emailreq = " required" if (cfg.signup_require_email or email_mode) else ""
    user_field = ("" if email_mode else
                  f"<label>{_e(t('reg.user'))}</label><input name=username required autofocus autocomplete=username autocapitalize=none autocorrect=off spellcheck=false>")
    body = (f"<h1>{_e(t('reg.title'))}</h1>"
            f"<form method=post action='__TS_P__/auth/register'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>"
            f"<input type=hidden name=invite value='{_e(ctx.get('invite', ''))}'>{_cf(ctx)}"
            f"{user_field}"
            + (f"<label>{_e(t('reg.email'))}</label>"
               f"<input name=email type=email value='{_e(ctx.get('email', ''))}'{emailro}{emailreq}"
               f"{' autofocus' if email_mode else ''} autocomplete=email>" if email_used else "") +
            f"<label>{_e(t('reg.password'))}</label><input name=password required type=password autocomplete=new-password>"
            f"<button type=submit>{_e(t('reg.submit'))}</button></form>"
            f"<div class=hint><a href='__TS_P__/auth/login'>{_e(t('reg.have'))}</a></div>")
    return _page(auth, t("reg.title"), body, below=messages, ctx=ctx)


def _magic_request(auth, ctx) -> str:
    """ctx: next, sent (bool), error. E-mail address for the login link."""
    t = auth.t
    if ctx.get("sent"):
        body = (f"<h1>{_e(t('magic.sent_title'))}</h1>"
                f"<div class=hint>{_e(t('magic.sent_hint'))}</div>"
                f"<a class=btn2 href='__TS_P__/auth/login'>{_e(t('magic.back_login'))}</a>")
        return _page(auth, t("magic.sent_title"), body, below=_messages([("ok", t("magic.sent"))]), ctx=ctx)
    messages = _messages([("error", ctx.get("error"))])
    body = (f"<h1>{_e(t('magic.title'))}</h1>"
            f"<div class=hint>{_e(t('magic.hint'))}</div>"
            f"<form method=post action='__TS_P__/auth/magic/request{_e(_app_q(ctx))}'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"<label>{_e(t('magic.email'))}</label>"
            f"<input name=email type=email autocomplete=email autofocus>"
            f"<button type=submit>{_e(t('magic.send'))}</button></form>"
            f"<div class=hint><a href='__TS_P__/auth/login'>{_e(t('back'))}</a></div>")
    return _page(auth, t("magic.title"), body, below=messages, ctx=ctx)


def _qr_code_shown(code) -> str:
    """The short code as it is read off the screen: two groups of four."""
    c = str(code or "")
    return f"{c[:4]}-{c[4:]}" if len(c) == 8 else c


def _qr_login(auth, ctx) -> str:
    """ctx: code, secret, approve_url (may be empty), qr (data URI or None), expires_at, next, error, match.

    The page of the NEW device (T-33): QR code and short code for the signed-in device, the
    secret only as a hidden field — whoever reads the screen gets the code, not the session.
    The script polls `/auth/qr/status` and submits the form as soon as the request is approved;
    without script the button does the same."""
    t = auth.t
    code = ctx.get("code", "")
    approve_url = ctx.get("approve_url") or ""
    where = approve_url.split("?", 1)[0] if approve_url else "__TS_P__/auth/qr/approve"
    qr = f"<img class=qr alt='' src='{_e(ctx['qr'])}'>" if ctx.get("qr") else ""
    body = (f"<h1>{_e(t('qr.title'))}</h1>"
            f"<div class=hint>{_e(t('qr.hint' if qr else 'qr.hint_code'))}</div>"
            f"{qr}"
            f"<div class=hint>{_e(t('qr.code_hint'))} <b>{_e(where)}</b></div>"
            f"<div class='mono qrcode'>{_e(_qr_code_shown(code))}</div>"
            # T-44 number matching: the approving device has to type this number — whoever got only
            # the approval link (phishing) does not see it.
            + (f"<div class=hint>{_e(t('qr.match_hint'))}</div>"
               f"<div class='mono qrcode qrmatch' id=qrmatch>{_e(ctx.get('match'))}</div>" if ctx.get("match") else "")
            + f"<form method=post action='__TS_P__/auth/qr/finish' id=tsqr>{_cf(ctx)}"
            f"<input type=hidden name=code value='{_e(code)}'>"
            f"<input type=hidden name=secret value='{_e(ctx.get('secret', ''))}'>"
            f"<button type=submit>{_e(t('qr.continue'))}</button></form>"
            f"<div class=hint id=qrstate role=status>{_e(t('qr.waiting'))}</div>"
            f"<div class=hint><a href='__TS_P__{_e(auth.cfg.login_path)}?next={_next_q(ctx.get('next') or '/')}'>"
            f"{_e(t('back'))}</a></div>"
            + _csrf_js(auth) +
            "<script>(function(){const f=document.getElementById('tsqr');let stop=false;"
            "async function poll(){if(stop)return;try{"
            "const r=await fetch('__TS_P__/auth/qr/status',{method:'POST',headers:{"
            "'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token':tsCsrf()},"
            "body:'code='+encodeURIComponent(f.code.value)+'&secret='+encodeURIComponent(f.secret.value)});"
            "const j=await r.json();"
            "if(j.state==='approved'){stop=true;f.submit();return}"
            f"if(j.state==='invalid'){{stop=true;document.getElementById('qrstate').textContent={json.dumps(t('qr.expired'))};return}}"
            "}catch(e){}setTimeout(poll,2000)}setTimeout(poll,2000)})()</script>")
    return _page(auth, t("qr.title"), body, below=_messages([("error", ctx.get("error"))]), ctx=ctx)


def _qr_approve(auth, ctx) -> str:
    """ctx: user, code, request_info (None or {ip, agent, created_at, …}), decided ('approved'|'denied'|None),
    error (a refusal shown above the page).

    The page of the SIGNED-IN device (T-33). Before anything is approved it names the device that
    asks — against a code someone else put on the screen (phishing). Without a code: a field for it."""
    import time as _time
    t = auth.t
    user = ctx.get("user") or {}
    decided = ctx.get("decided")
    if decided in ("approved", "denied"):
        body = (f"<h1>{_e(t('qr.' + decided + '_title'))}</h1>"
                f"<div class=hint>{_e(t('qr.' + decided + '_hint'))}</div>"
                f"<a class=btn2 href='__TS_P__/'>{_e(t('error.home'))}</a>")
        return _page(auth, t("qr." + decided + "_title"), body, ctx=ctx)
    info = ctx.get("request_info")
    below = _messages([("error", ctx.get("error"))])
    if not info:
        body = (f"<h1>{_e(t('qr.approve_title'))}</h1>"
                f"<div class=hint>{_e(t('qr.enter_code'))}</div>"
                f"<form method=get action='__TS_P__/auth/qr/approve'>"
                f"<label>{_e(t('qr.code'))}</label>"
                f"<input name=code class=code autocomplete=off autocapitalize=characters spellcheck=false autofocus>"
                f"<button type=submit>{_e(t('qr.check'))}</button></form>")
        return _page(auth, t("qr.approve_title"), body, below=below, ctx=ctx)
    age = max(0, int(_time.time()) - int(info.get("created_at") or 0))
    code = ctx.get("code", "")
    body = (f"<h1>{_e(t('qr.approve_title'))}</h1>"
            f"<div class=hint>{_e(t('qr.approve_hint', user=user.get('username', '')))}</div>"
            f"<table class=qrinfo>"
            f"<tr><th>{_e(t('qr.code'))}</th><td class=mono>{_e(_qr_code_shown(code))}</td></tr>"
            f"<tr><th>{_e(t('qr.ip'))}</th><td>{_e(info.get('ip') or '—')}</td></tr>"
            f"<tr><th>{_e(t('qr.device'))}</th><td>{_e(info.get('agent') or '—')}</td></tr>"
            f"<tr><th>{_e(t('qr.asked'))}</th><td>{_e(t('qr.asked_ago', sec=age))}</td></tr></table>"
            # T-44: the warning against consent phishing, and the number from the other screen.
            f"<div class=warnbar id=qrwarn>{_e(t('qr.warning'))}</div>"
            f"<form method=post action='__TS_P__/auth/qr/approve' id=qrapprove>{_cf(ctx)}"
            f"<input type=hidden name=code value='{_e(code)}'>"
            f"<label for=qrmatchin>{_e(t('qr.match'))}</label>"
            f"<input id=qrmatchin name=match class=code inputmode=numeric pattern='[0-9]{{2}}' maxlength=2 "
            f"autocomplete=off required autofocus>"
            f"<button type=submit>{_e(t('qr.approve'))}</button></form>"
            f"<form method=post action='__TS_P__/auth/qr/deny'>{_cf(ctx)}"
            f"<input type=hidden name=code value='{_e(code)}'>"
            f"<button type=submit class=btn2>{_e(t('qr.deny'))}</button></form>")
    return _page(auth, t("qr.approve_title"), body, below=below, ctx=ctx)


def _forgot(auth, ctx) -> str:
    """ctx: sent (bool), error. E-mail for the reset link."""
    t = auth.t
    if ctx.get("sent"):
        return _page(auth, t("magic.sent_title"),
                      f"<h1>{_e(t('magic.sent_title'))}</h1>"
                      f"<a class=btn2 href='__TS_P__/auth/login'>{_e(t('magic.to_login'))}</a>",
                      below=_messages([("ok", t("magic.sent"))]), ctx=ctx)
    messages = _messages([("error", ctx.get("error"))])
    body = (f"<h1>{_e(t('forgot.title'))}</h1>"
            f"<div class=hint>{_e(t('forgot.hint'))}</div>"
            f"<form method=post action='__TS_P__/auth/forgot{_e(_app_q(ctx))}'>{_cf(ctx)}"
            f"<label>{_e(t('magic.email'))}</label><input name=email type=email autocomplete=email autofocus>"
            f"<button type=submit>{_e(t('forgot.send'))}</button></form>"
            f"<div class=hint><a href='__TS_P__/auth/login'>{_e(t('back'))}</a></div>")
    return _page(auth, t("forgot.title"), body, below=messages, ctx=ctx)


def _reset(auth, ctx) -> str:
    """ctx: token, error. Set a new password."""
    t = auth.t
    messages = _messages([("error", ctx.get("error"))])
    body = (f"<h1>{_e(t('reset.title'))}</h1>"
            f"<form method=post action='__TS_P__/auth/reset'>"
            f"<input type=hidden name=token value='{_e(ctx.get('token', ''))}'>{_cf(ctx)}"
            f"<label>{_e(t('reset.new'))}</label>"
            f"<input name=password type=password autocomplete=new-password autofocus>"
            f"<button type=submit>{_e(t('reset.submit'))}</button></form>")
    return _page(auth, t("reset.title"), body, below=messages, ctx=ctx)


def _error(auth, ctx) -> str:
    """ctx: code, message. Themed error page (403/404/429/500 …). Replaceable via set_template('error')."""
    t = auth.t
    code = ctx.get("code", 500)
    msg = ctx.get("message") or t("error.oops")
    body = (f"<h1 class=errcode>{_e(code)}</h1>"
            f"<div class='hint errhint'>{_e(msg)}</div>"
            f"<a class=btn2 href='__TS_P__/'>{_e(t('error.home'))}</a>")
    return _page(auth, str(code), body, ctx=ctx)


def _magic_confirm(auth, ctx) -> str:
    """ctx: purpose ('login'|'verify_email'|'email_change'), action. A button that redeems the
    one-time link (R4-02).

    The link from the mail no longer redeems on GET — mail scanners open every link and
    would otherwise have consumed it. Only this POST (with CSRF token) does it."""
    t = auth.t
    button = {"verify_email": t("magic.confirm_verify"),
             "email_change": t("magic.confirm_email_change")}.get(ctx.get("purpose"), t("magic.confirm_login"))
    body = (f"<h1>{_e(t('magic.confirm_title'))}</h1>"
            f"<div class=hint>{_e(t('magic.confirm_hint'))}</div>"
            f"<form method=post action='{_e(ctx.get('action', ''))}'>{_cf(ctx)}"
            f"<button type=submit autofocus>{_e(button)}</button></form>")
    return _page(auth, t("magic.confirm_title"), body, ctx=ctx)


def _revoke_js(auth, back: str) -> str:
    """JS for the offer after a factor change (B1-7, ASVS 7.4.3): `offer(r)` reads
    `other_sessions` from the response and asks, `tsRevokeOthers()` ends the remaining
    sessions. Needs `tsCsrf()` on the page.

    Ending requires a fresh confirmation (F-09), creating a factor does not always
    (passkey, TOTP need only a session). If the freshness has expired, the path leads through
    the reauth page — and `back` (a JS expression, or empty) says where to go afterwards,
    so that the consent already given is not silently lost (A-5). During
    this redirect `tsRevokeOthers` never returns: a caller that reloads afterwards
    would otherwise abort the navigation."""
    t = auth.t
    destination = (f"location.href=re+'?next='+encodeURIComponent({back});return new Promise(()=>{{}})"
            if back else f"await tsAlert({json.dumps(t('api.stepup'))});return false")
    return ("<script>"
            "async function tsRevokeOthers(){const r=await fetch('__TS_P__/auth/sessions/revoke',{method:'POST',"
            "headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},"
            "body:JSON.stringify({scope:'others'})});"
            "const re=r.headers.get('X-TinySesam-Reauth');"
            f"if(r.status===403&&re){{{destination}}}return r.ok}}"
            "async function offer(r){let j={};try{j=await r.clone().json()}catch(e){}"
            f"if(r.ok&&j.other_sessions>0&&await tsConfirm({json.dumps(t('acc.sessions_offer'))}))"
            "await tsRevokeOthers();"
            # Boundary d: in the middle of the chain — note it, redeemed at the end.
            f"if(r.ok&&j.other_sessions_after>0&&await tsConfirm({json.dumps(t('acc.sessions_offer'))}))"
            "await fetch('__TS_P__/auth/sessions/revoke-after-login',{method:'POST',"
            "headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},body:'{}'})}</script>")


# Back from reauth with `?revoke_others=1`: ask once more, then end. Not silently
# executed — otherwise every foreign link to this address would end the other sessions.
_ACCOUNT_RETURN_JS = """<script>
if(new URLSearchParams(location.search).get('revoke_others')==='1'){
  const keep=new URLSearchParams(location.search);keep.delete('revoke_others');
  history.replaceState(null,'',location.pathname+(keep.toString()?'?'+keep.toString():''));
  tsConfirm(__CONFIRM__,{danger:true}).then(yes=>{if(yes)tsRevokeOthers().then(ok=>{if(ok)say('sess_msg',TXT.ended,true);loadsess()})})}
</script>"""


def _logout(auth, ctx) -> str:
    """ctx: — . Confirmation prompt before signing out, when the link came from a foreign page (F-07).
    A POST form with a CSRF field; the GET itself does not sign out in this case."""
    t = auth.t
    body = (f"<h1>{_e(t('logout'))}</h1>"
            f"<div class=hint>{_e(t('logout.confirm'))}</div>"
            f"<form method=post action='__TS_P__/auth/logout'>{_cf(ctx)}"
            f"<button type=submit>{_e(t('logout'))}</button></form>"
            f"<div class=hint><a href='__TS_P__/'>{_e(t('cancel'))}</a></div>")
    return _page(auth, t("logout"), body, ctx=ctx)


def _gate_logout(auth, ctx) -> str:
    """ctx: scope ("" = ask, otherwise "app"/"all" for confirmation), app_name, next. Lives on the
    app's host under /.tinysesam/ — the forms therefore target `logout` relatively."""
    t = auth.t
    name = ctx.get("app_name") or t("gate.this_app")

    def button(scope, text):
        return (f"<form method=post action='logout'>{_cf(ctx)}"
                f"<input type=hidden name=scope value='{_e(scope)}'>"
                f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>"
                f"<button type=submit>{_e(text)}</button></form>")

    if ctx.get("scope") in ("app", "all"):
        question = t("gate.confirm_app", name=name) if ctx["scope"] == "app" else t("gate.confirm_all")
        buttons = button(ctx["scope"], t("logout"))
    else:
        question = t("gate.ask", name=name)
        buttons = button("app", t("gate.only_app", name=name)) + button("all", t("gate.everywhere"))
    body = (f"<h1>{_e(t('logout'))}</h1><div class=hint>{_e(question)}</div>{buttons}"
            f"<div class=hint><a href='/'>{_e(t('cancel'))}</a></div>")
    return _page(auth, t("logout"), body, ctx=ctx)


def _gate_logged_out(auth, ctx) -> str:
    """ctx: app_name, again_url (optional, default "/" of the host), redirect_sec (optional). After signing out — with
    a way back that starts a NEW sign-in. With `redirect_sec` > 0 ("direct" mode, PO 2026-10-10) it goes
    there by itself after that many seconds: a meta refresh, no script; the bar runs down in CSS only."""
    t = auth.t
    destination = ctx.get("again_url") or "/"
    try:
        sec = max(0, min(300, int(ctx.get("redirect_sec") or 0)))
    except (TypeError, ValueError):
        sec = 0
    head, further = "", ""
    if sec:
        head = (f"<meta http-equiv=refresh content='{sec};url={_e(destination)}'>"
                f"<style>@keyframes tsweiter{{from{{transform:scaleX(1)}}to{{transform:scaleX(0)}}}}"
                f".tsweiter i{{animation:tsweiter {sec}s linear forwards}}</style>")
        further = (f"<div class=hint role=status>{_e(t('gate.login_soon', n=sec))}</div>"
                  f"<div class=tsweiter aria-hidden=true><i></i></div>")
    body = (f"<h1>{_e(t('gate.logged_out_title'))}</h1><div class=hint>{_e(t('gate.logged_out'))}</div>{further}"
            f"<a class=btn2 href='{_e(destination)}'>{_e(t('gate.login_now') if sec else t('gate.login_again'))}</a>")
    return _page(auth, t("gate.logged_out_title"), body, head=head, ctx=ctx)


def _gateway_home(auth, ctx) -> str:
    """ctx: user_name. Gateway start page for signed-in users — whoever opens `/` sees who they are
    signed in as, and can sign out. (Until 0.24.1 `/` answered with a JSON 404.)"""
    t = auth.t
    body = (f"<h1>{_e(t('gw.title'))}</h1>"
            f"<div class=hint>{_e(t('gw.signed_in_as', name=ctx.get('user_name', '')))}</div>"
            f"<div class=hint>{_e(t('gw.hint'))}</div>"
            f"<form method=post action='__TS_P__/auth/logout'>{_cf(ctx)}"
            f"<button type=submit>{_e(t('logout'))}</button></form>")
    return _page(auth, t("gw.title"), body, ctx=ctx)


def _magic_invalid(auth, ctx) -> str:
    t = auth.t
    body = (f"<h1>{_e(t('magic.invalid_title'))}</h1>"
            f"<a class=btn2 href='__TS_P__/auth/login'>{_e(t('magic.to_login'))}</a>")
    return _page(auth, t("magic.invalid_title"), body,
                 below=_messages([("error", ctx.get("message") or t("magic.invalid"))]), ctx=ctx)


def _resource_unlock(auth, ctx) -> str:
    """ctx: name, kind ('pin'|'password'), label, next, error. Shared resource secret."""
    t = auth.t
    messages = _messages([("error", ctx.get("error"))])
    if ctx.get("kind") == "pin":
        field = "<input name=secret type=password inputmode=numeric autocomplete=off class=code autofocus>"
        lbl = t("res.pin")
    else:
        field = "<input name=secret type=password autocomplete=off autofocus>"
        lbl = t("res.word")
    body = (f"<h1>{_e(ctx.get('label'))}</h1>"
            f"<div class=hint>{_e(t('res.hint', kind=lbl))}</div>"
            f"<form method=post action='__TS_P__/auth/resource/{_e(ctx.get('name'))}'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"<label>{_e(lbl)}</label>{field}"
            f"<button type=submit>{_e(t('res.submit'))}</button></form>")
    return _page(auth, str(ctx.get("label") or lbl), body, below=messages, ctx=ctx)


def _stepup_field(auth, method, first) -> str:
    """One input field per step-up method. `first` gets the focus."""
    t = auth.t
    fc = " autofocus" if first else ""
    if method == "totp":
        return (f"<label>{_e(t('totp.label'))}</label>"
                f"<input name=code class=code inputmode=numeric autocomplete=one-time-code{fc} maxlength=6>")
    if method == "pin":
        return (f"<label>{_e(t('reauth.pin'))}</label>"
                f"<input name=pin type=password inputmode=numeric autocomplete=off class=code{fc}>")
    return (f"<label>{_e(t('reauth.pw'))}</label>"
            f"<input name=password type=password autocomplete=current-password{fc}>")


def _reauth(auth, ctx) -> str:
    """ctx: next, error, username, methods (list from auth.stepup_options).
    Sudo freshness: confirm a factor again (step-up).

    An **empty** methods list is a statement and not a missing value: this account has
    nothing with which it could confirm here (`stepup_strict`, or no factor
    set up yet). Then there is NO form here. Before, the empty list fell back to
    `["password"]` and the page offered a password field that a purely federated
    account does not have — the user tried something that cannot succeed, and every attempt
    counted into the same lockout bucket. If the key is missing entirely (custom callers, preview),
    the password field stays.
    """
    t = auth.t
    messages = _messages([("error", ctx.get("error"))])
    methods = ctx.get("methods")
    methods = ["password"] if methods is None else list(methods)
    head = (f"<h1>{_e(t('reauth.title'))}</h1>"
            f"<div class=hint>{_e(t('reauth.hint', user=ctx.get('username')))}</div>")
    fuss = f"<div class=hint><a href='__TS_P__/auth/logout'>{_e(t('logout'))}</a></div>"
    # T-49: an account linked to the provider confirms there — with an active sign-in (`prompt=login`), checked by
    # its `auth_time`. For a purely federated account it is the only way that does not end the session.
    if ctx.get("reauth_oidc"):
        fuss = (f"<a class=btn2 id=reauthoidc href='__TS_P__/auth/oidc/start?reauth=1&amp;next="
                f"{_next_q(ctx.get('next') or '/')}'>{_e(t('reauth.oidc', name=auth.cfg.oidc_name))}</a>" + fuss)
    # T-70: the same for an account bound to the SAML provider — `ForceAuthn`, checked by the `AuthnInstant`.
    if ctx.get("reauth_saml"):
        fuss = (f"<a class=btn2 id=reauthsaml href='__TS_P__/auth/saml/login?reauth=1&amp;next="
                f"{_next_q(ctx.get('next') or '/')}'>{_e(t('reauth.oidc', name=auth.cfg.saml_name))}</a>" + fuss)
    if not methods:
        return _page(auth, t("reauth.title"), head + fuss, below=messages, ctx=ctx)
    fields = f"<div class=or>{_e(t('or'))}</div>".join(
        _stepup_field(auth, m, i == 0) for i, m in enumerate(methods))
    body = (head
            + f"<form method=post action='__TS_P__/auth/reauth'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"{fields}<button type=submit>{_e(t('reauth.submit'))}</button></form>"
            + fuss)
    return _page(auth, t("reauth.title"), body, below=messages, ctx=ctx)


def _pin(auth, ctx) -> str:
    """ctx: next, error, username (optional). PIN entry — without a user field if already signed in."""
    t = auth.t
    messages = _messages([("error", ctx.get("error"))])
    known = bool(ctx.get("username"))
    id_label, id_ac = _ident(auth)
    user_field = ("" if known else
                  f"<label>{_e(id_label)}</label><input name=username autofocus autocomplete={id_ac} autocapitalize=none autocorrect=off spellcheck=false>")
    hint = (f"<div class=hint>{_e(t('reauth.hint', user=ctx.get('username')))}</div>" if known else "")
    body = (f"<h1>{_e(t('pin.title'))}</h1>{hint}"
            f"<form method=post action='__TS_P__/auth/pin'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"{user_field}"
            f"<label>{_e(t('login.pin'))}</label>"
            f"<input name=pin type=password inputmode=numeric autocomplete=off class=code"
            f"{' autofocus' if known else ''}>"
            f"<button type=submit>{_e(t('login.pin_submit'))}</button></form>"
            f"<div class=hint><a href='__TS_P__{_e(auth.cfg.login_path)}'>{_e(t('back'))}</a></div>")
    return _page(auth, t("pin.title"), body, top=_demobar(auth, pin=True, ctx=ctx), below=messages, ctx=ctx)


def _totp_app_hint(cfg) -> str:
    """`totp_app_hint` in the page's language (`lang`, else `en`, else the first entry) — or "". Fail-closed for a
    value changed at runtime: only a text that `config_check` would accept is shown."""
    from .config_check import totp_app_hint_ok
    hints = getattr(cfg, "totp_app_hint", None)
    if not isinstance(hints, dict) or not hints:
        return ""
    lang = str(getattr(cfg, "lang", "en") or "en")
    text = hints.get(lang) or hints.get("en") or next(iter(hints.values()), "")
    return text if totp_app_hint_ok(text) else ""


def _totp_setup(auth, ctx) -> str:
    """ctx: data = {secret, uri, qr} — or `None`/missing for the first step.

    Two states, one page: without `data` there is only a POST form that explicitly
    starts the setup. The secret is created only with this click (B2-1) — a GET that creates
    one can be triggered from a foreign page and invalidates an attempt in progress.
    """
    t = auth.t
    data = ctx.get("data")
    # T-94: the operator's hint (which app to install), escaped, on both steps — before the start and above the QR.
    app_hint = _totp_app_hint(auth.cfg)
    app_hint = f"<div class=hint id=totp_app_hint>{_e(app_hint)}</div>" if app_hint else ""
    if not data:
        body = (f"<h1>{_e(t('setup.title'))}</h1>{app_hint}"
                f"<div class=hint>{_e(t('setup.start_hint'))}</div>"
                f"<form method=post action='__TS_P__/auth/totp/setup/start'>{_cf(ctx)}"
                f"<input type=hidden name=next value='{_e(ctx.get('next') or '/')}'>"
                f"<button type=submit>{_e(t('setup.start'))}</button></form>")
        return _page(auth, t("setup.title"), body, ctx=ctx)
    qr = f"<img class=qr src='{data['qr']}'>" if data.get("qr") else ""
    ok_msg = _e(t("setup.ok")).replace("'", "\\'")
    bad_msg = _e(t("err.code")).replace("'", "\\'")
    body = (f"<h1>{_e(t('setup.title'))}</h1>{app_hint}"
            f"<div class=hint>{_e(t('setup.scan'))}</div>"
            f"{qr}"
            f"<div class=hint>{_e(t('setup.manual'))}</div><div class=mono>{_e(data['secret'])}</div>"
            f"<form id=tstotp data-next='{_e(ctx.get('next') or '/')}'>"
            f"<label>{_e(t('setup.code'))}</label>"
            f"<input name=code class=code inputmode=numeric maxlength=6 autofocus>"
            f"<button type=submit>{_e(t('setup.activate'))}</button></form>"
            f"<div class=hint id=msg></div>"
            # B-9a: the recovery codes, once, right after activation — hidden until then.
            f"<div id=rcbox hidden><div class=hint>{_e(t('setup.recovery_note'))}</div>"
            f"<pre id=rccodes class='mono rccodes'></pre>"
            # T-35: a copy button; without the clipboard API it selects the codes for Ctrl+C.
            f"<div class=rccopyrow><button type=button id=rccopy class=btn2>{_e(t('dlg.copy'))}</button>"
            f"<span id=rcstate class=rcstate role=status aria-live=polite></span></div>"
            f"<button type=button id=rcdone>{_e(t('setup.recovery_done'))}</button></div>"
            + _dialog.assets(auth) +
            "<script>function tsCsrf(){return (document.cookie.match(/(?:^|; )" + _e(auth.csrf_cookie_name) + "=([^;]+)/)||[])[1]||''}"
            "async function conf(e){e.preventDefault();const f=e.target,c=f.code.value;"
            "const r=await fetch('__TS_P__/auth/totp/setup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token':tsCsrf()},"
            "body:'code='+encodeURIComponent(c)+'&next='+encodeURIComponent(f.dataset.next||'/')});"
            "const j=await r.clone().json();"
            f"document.getElementById('msg').textContent=j.ok?'{ok_msg}':'{bad_msg}';"
            # B1-7 on this page too (A-5): it is the path on which TOTP comes into being.
            "await offer(r);"
            "if(!j.ok)return false;"
            # On to the target (B-8; under the mandatory chain the sign-in is complete with the
            # confirmation, A-1) — but only once the codes are noted, otherwise they are gone for good.
            "const go=()=>{location.href=j.next||f.dataset.next||'/'};"
            "const codes=j.recovery_codes||[];"
            "if(!codes.length){go();return false}"
            "f.hidden=true;document.getElementById('rccodes').textContent=codes.join('\\n');"
            "const box=document.getElementById('rcbox');box.hidden=false;"
            "document.getElementById('rcdone').addEventListener('click',go);"
            "document.getElementById('rcdone').focus();return false}"
            "document.getElementById('tstotp').addEventListener('submit',conf);"
            "document.getElementById('rccopy').addEventListener('click',async()=>{"
            "const ok=await tsCopy(document.getElementById('rccodes').textContent,document.getElementById('rccodes'));"
            "const st=document.getElementById('rcstate');"
            f"st.textContent=ok?{json.dumps(t('dlg.copied'))}:{json.dumps(t('dlg.copy_manual'))};"
            "st.className='rcstate'+(ok?'':' manual')})</script>"
            + _revoke_js(auth, "'__TS_P__/auth/account?revoke_others=1'"
                         if getattr(auth.cfg, "account_enabled", False) else ""))
    return _page(auth, t("setup.title"), body, ctx=ctx)


def _account_setup(auth, ctx) -> str:
    """The setup pass after a sign-in link (T-34). ctx: options (factor names to choose from),
    left (steps still missing, this one included), next, pin_min (minimum PIN length).

    One card per pass step: a single option is shown on its own, several as a choice. Password and
    PIN post JSON to their setup routes, the passkey registers through WebAuthn, TOTP leads to its
    own setup page. Every answer carries `next` — the following step or the target."""
    t = auth.t
    options = list(ctx.get("options") or [])
    nxt = ctx.get("next") or "/"
    # T-46: the same page replaces the administrator's start secret (`renew`) — one password card.
    renew = bool(ctx.get("renew"))
    blocks = []
    for f in options:
        if f == "password":
            blocks.append(
                f"<form class=obopt id=ob_password><h2>{_e(t('onboard.password'))}</h2>"
                f"<div class=obhint>{_e(t('onboard.renew_hint' if renew else 'onboard.password_hint'))}</div>"
                f"<label for=ob_pw1>{_e(t('onboard.password_new'))}</label>"
                f"<input id=ob_pw1 type=password autocomplete=new-password required>"
                f"<label for=ob_pw2>{_e(t('onboard.password_repeat'))}</label>"
                f"<input id=ob_pw2 type=password autocomplete=new-password required>"
                f"<button type=submit>{_e(t('onboard.password_set'))}</button></form>")
        elif f == "pin":
            blocks.append(
                f"<form class=obopt id=ob_pin><h2>{_e(t('onboard.pin'))}</h2>"
                f"<div class=obhint>{_e(t('onboard.pin_hint', n=ctx.get('pin_min', 4)))}</div>"
                f"<label for=ob_pin1>{_e(t('onboard.pin_new'))}</label>"
                f"<input id=ob_pin1 type=password inputmode=numeric autocomplete=off required>"
                f"<button type=submit>{_e(t('onboard.pin_set'))}</button></form>")
        elif f == "totp":
            blocks.append(
                f"<div class=obopt id=ob_totp><h2>{_e(t('onboard.totp'))}</h2>"
                f"<div class=obhint>{_e(t('onboard.totp_hint'))}</div>"
                f"<a class=btn2 href='__TS_P__/auth/totp/setup?next={_next_q(nxt)}'>{_e(t('onboard.totp_go'))}</a></div>")
        elif f == "passkey":
            blocks.append(
                f"<div class=obopt id=ob_passkey><h2>{_e(t('onboard.passkey'))}</h2>"
                f"<div class=obhint>{_e(t('onboard.passkey_hint'))}</div>"
                f"<button type=button id=ob_pkbtn>{_e(t('onboard.passkey_go'))}</button></div>")
    left = int(ctx.get("left") or 1)
    choose = f"<div class=obchoose>{_e(t('onboard.choose'))}</div>" if len(options) > 1 else ""
    css = ("<style>.tsmain .obopt{border-top:1px solid var(--ts-line-soft);margin-top:16px;padding-top:12px}"
           ".tsmain .obopt h2{font-size:15px;margin:0 0 4px}"
           ".tsmain .obhint,.tsmain .obchoose,.tsmain .obleft{color:var(--ts-muted);font-size:13px;margin:4px 0 8px}"
           ".tsmain .obmsg{color:var(--ts-err-ink);font-size:13px;margin-top:12px}</style>")
    texts = json.dumps({"mismatch": t("onboard.mismatch"), "failed": t("onboard.failed")})
    script = ("<script>"
              "function tsCsrf(){return (document.cookie.match(/(?:^|; )" + _e(auth.csrf_cookie_name)
              + "=([^;]+)/)||[])[1]||''}"
              "const OB=" + texts + ",NEXT=document.getElementById('obroot').dataset.next;"
              "function obsay(m){const e=document.getElementById('obmsg');e.textContent=m;e.hidden=!m}"
              "async function obpost(u,b){const r=await fetch(u,{method:'POST',headers:{'Content-Type':"
              "'application/json','X-CSRF-Token':tsCsrf()},body:JSON.stringify(b)});"
              "let j={};try{j=await r.json()}catch(e){}return [r,j]}"
              "function obdone(r,j){if(r.ok&&j.next){location.href=j.next;return}"
              "obsay(OB.failed+(j.detail?': '+j.detail:''))}"
              "const pw=document.getElementById('ob_password');"
              "if(pw)pw.addEventListener('submit',async e=>{e.preventDefault();"
              "const a=document.getElementById('ob_pw1').value,b=document.getElementById('ob_pw2').value;"
              "if(a!==b){obsay(OB.mismatch);return}"
              "const [r,j]=await obpost('__TS_P__/auth/password/set',{new:a,next:NEXT});obdone(r,j)});"
              "const pn=document.getElementById('ob_pin');"
              "if(pn)pn.addEventListener('submit',async e=>{e.preventDefault();"
              "const [r,j]=await obpost('__TS_P__/auth/pin/set',{pin:document.getElementById('ob_pin1').value,next:NEXT});"
              "obdone(r,j)});"
              "const pk=document.getElementById('ob_pkbtn');"
              "const b64=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));"
              "const enc=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-')"
              ".replace(/\\//g,'_').replace(/=+$/,'');"
              "if(pk)pk.addEventListener('click',async()=>{try{"
              "const o=await (await fetch('__TS_P__/auth/passkey/register/begin',{method:'POST',"
              "headers:{'X-CSRF-Token':tsCsrf()}})).json();"
              "o.challenge=b64(o.challenge);o.user.id=b64(o.user.id);"
              "(o.excludeCredentials||[]).forEach(c=>c.id=b64(c.id));"
              "const c=await navigator.credentials.create({publicKey:o});"
              "const body={id:c.id,rawId:enc(c.rawId),type:c.type,response:{clientDataJSON:"
              "enc(c.response.clientDataJSON),attestationObject:enc(c.response.attestationObject),"
              "transports:(c.response.getTransports&&c.response.getTransports())||[]}};"
              "const r=await fetch('__TS_P__/auth/passkey/register/finish?next='+encodeURIComponent(NEXT),"
              "{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},"
              "body:JSON.stringify(body)});let j={};try{j=await r.json()}catch(e){}obdone(r,j)"
              "}catch(e){obsay(OB.failed+': '+e)}});"
              "</script>")
    body = (f"{css}<div id=obroot data-next='{_e(nxt)}'>"
            f"<h1>{_e(t('onboard.renew_title' if renew else 'onboard.title'))}</h1>"
            + ("" if renew else f"<div class=obhint>{_e(t('onboard.hint'))}</div>"
                                f"<div class=obleft>{_e(t('onboard.left', n=left))}</div>")
            + f"{choose}{''.join(blocks)}"
            f"<div id=obmsg class=obmsg role=alert hidden></div>"
            f"<div class=hint><a href='__TS_P__/auth/logout'>{_e(t('cancel'))}</a></div></div>"
            + ("" if ctx.get("static") else script))
    return _page(auth, t("onboard.renew_title" if renew else "onboard.title"), body, ctx=ctx)


#: The consent page for laypeople (ADR-14, option e): one question, one large button, the technical part folded away.
_CONSENT_CSS = """
.tsmain .oalead{font-size:17px;line-height:1.45;margin:4px 0 6px}
.tsmain .oalead bdi{font-weight:600}
.tsmain .oaonly{color:var(--ts-muted);font-size:14px;margin:0 0 4px}
.tsmain #oaallow{font-size:18px;padding:15px;min-height:52px}
.tsmain #oadetails{margin-top:18px;border-top:1px solid var(--ts-line);padding-top:10px}
.tsmain #oadetails summary{cursor:pointer;padding:12px 0;color:var(--ts-muted)}
.tsmain #oadetails table{margin-top:6px}
.tsmain #oadetails td{overflow-wrap:anywhere}
"""


def _oauth_consent(auth, ctx) -> str:
    """ctx: user, txn, client_name, client_id, redirect_host, resource, resource_name, scope (list), offline,
    access_minutes, idle_days, max_days (0 = no maximum). The consent of an OAuth client (T-36): which program
    asks, where the answer goes, what it may do and for how long — before anything is allowed.

    Written for laypeople (ADR-14, option e): the question in one sentence with the application's name (from
    `forward_apps`, the frame of T-91 around it), one large "Allow", and program, `client_id`, redirect host, address,
    scope and duration in a `<details>` that opens on a click."""
    t = auth.t
    user = ctx.get("user") or {}
    target = ctx.get("resource_name") or ctx.get("resource") or ""
    if ctx.get("offline"):
        duration = t("oauth.duration_refresh", days=ctx.get("idle_days", 0))
        if ctx.get("max_days"):
            duration += " " + t("oauth.duration_max", days=ctx.get("max_days"))
    else:
        duration = t("oauth.duration_access", minutes=ctx.get("access_minutes", 60))
    lead = _e(t("oauth.consent_lead", client="\x00c", resource="\x00r", user="\x00u")).replace(
        "\x00c", f"<bdi>{_e(ctx.get('client_name', ''))}</bdi>").replace(
        "\x00r", f"<bdi>{_e(target)}</bdi>").replace("\x00u", f"<bdi>{_e(user.get('username', ''))}</bdi>")
    scope = " ".join(ctx.get("scope") or [])
    body = (f"<h1>{_e(t('oauth.consent_title'))}</h1>"
            f"<p class=oalead id=oalead>{lead}</p>"
            f"<p class=oaonly>{_e(t('oauth.consent_only'))}</p>"
            f"<form method=post action='__TS_P__/auth/oauth/consent'>{_cf(ctx)}"
            f"<input type=hidden name=txn value='{_e(ctx.get('txn', ''))}'>"
            f"<button type=submit id=oaallow name=decision value=allow>{_e(t('oauth.allow'))}</button>"
            f"<button type=submit id=oadeny class=btn2 name=decision value=deny>{_e(t('oauth.deny'))}</button></form>"
            f"<details id=oadetails><summary>{_e(t('oauth.details'))}</summary>"
            f"<table class=qrinfo>"
            f"<tr><th>{_e(t('oauth.client'))}</th><td id=oaclient>{_e(ctx.get('client_name', ''))}<br>"
            f"<small>{_e(t('oauth.unverified'))} · <code>{_e(ctx.get('client_id', ''))}</code></small></td></tr>"
            f"<tr><th>{_e(t('oauth.redirect'))}</th><td id=oarhost class=mono>{_e(ctx.get('redirect_host', ''))}</td></tr>"
            f"<tr><th>{_e(t('oauth.resource'))}</th><td id=oaresource>{_e(target)}"
            + (f"<br><small>{_e(ctx.get('resource', ''))}</small>" if ctx.get("resource_name") else "")
            + f"</td></tr><tr><th>{_e(t('oauth.scope'))}</th><td id=oascope class=mono>{_e(scope)}</td></tr>"
            f"<tr><th>{_e(t('oauth.duration'))}</th><td>{_e(duration)}</td></tr></table>"
            f"<div class=warnbar>{_e(t('oauth.local_warning', host=ctx.get('redirect_host', '')))}</div></details>")
    return _page(auth, t("oauth.consent_title"), body, head=f"<style>{_CONSENT_CSS}</style>", ctx=ctx)


def _oauth_return(auth, ctx) -> str:
    """ctx: url (the program's loopback callback with code, state, iss), client_name. After a pairing code allowed
    the request (ADR-14): straight back to the program by a meta refresh — a navigation, not a redirect, so the
    `form-action` of a sign-in page earlier in the chain does not stop it — and a link for a browser that waits."""
    t = auth.t
    url = str(ctx.get("url") or "")
    body = (f"<h1>{_e(t('oauth.return_title'))}</h1>"
            f"<p class=hint id=oareturn>{_e(t('oauth.return_hint', client=ctx.get('client_name', '')))}</p>"
            f"<p><a id=oareturnlink href='{_e(url)}'>{_e(t('oauth.return_link'))}</a></p>")
    return _page(auth, t("oauth.return_title"), body, head=f"<meta http-equiv=refresh content='0;url={_e(url)}'>",
                 ctx=ctx)


_APPROVAL_CSS = """
.tsmain .apvsum{font-size:15px;line-height:1.45;margin:0 0 6px}
.tsmain .apvsum bdi{font-weight:600}
.tsmain .apvcode{font-family:var(--ts-mono);font-size:26px;letter-spacing:.12em;text-align:center;margin:6px 0 2px;
     padding:8px;border:1px dashed var(--ts-line);border-radius:8px}
.tsmain .apvmeta{color:var(--ts-muted);font-size:12px;margin-top:10px}
.tsmain .apvlist{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:8px}
.tsmain .apvlist a{display:block;padding:12px;border:1px solid var(--ts-line);border-radius:8px;color:var(--ts-ink);
     text-decoration:none;min-height:44px}
.tsmain .apvlist a:hover{background:var(--ts-surface-2)}
.tsmain .apvlist small{display:block;color:var(--ts-muted);margin-top:4px}
.tsmain .apvbtns{display:flex;gap:10px}
.tsmain .apvbtns button{flex:1;min-height:44px;margin-top:18px}
.tsmain .apvstate{font-weight:600}
.tsmain #apvirrev{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600}
.tsmain .apvwarn{flex:0 0 18px;width:18px;height:18px}
.tsmain .apvsr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
"""

#: Words for the state of a closed approval — a symbol of `_SYMBOL` and a word, never colour alone.
_APV_STATE_KIND = {"consumed": "ok", "rejected": "info", "expired": "warn", "withdrawn": "info", "approved": "ok"}


def _approval_rows(rows) -> str:
    return "".join(f"<tr><th>{_e(k)}</th><td><bdi>{_e(v)}</bdi></td></tr>" for k, v in rows)


def _approval_summary(a) -> str:
    """The summary: a TinySesam action's sentence, or an application action's operator text with every field value
    escaped AND bidi-isolated on its own (`<bdi>`), so a value can neither break out as markup nor reorder the text
    around it."""
    parts = a.get("summary_parts")
    if parts:
        inner = "".join(f"<bdi>{_e(text)}</bdi>" if is_value else _e(text) for text, is_value in parts)
        return f"<p class=apvsum id=apvsum>{inner}</p>"
    return f"<p class=apvsum id=apvsum><bdi>{_e(a.get('summary'))}</bdi></p>"


def _approvals(auth, ctx) -> str:
    """ctx: items (views from `Approvals.view`). The person's open approvals — one link per request, no bulk
    confirmation (each request is decided on its own page with its own step-up)."""
    t = auth.t
    items = ctx.get("items") or []
    if items:
        lis = "".join(
            f"<li><a href='__TS_P__/auth/approvals/{_e(a['id'])}{_e(_app_q(ctx))}' data-apv='{_e(a['id'])}'>"
            f"<b>{_e(a['title'])}</b><small>{_e(t('apv.code'))} <span class=mono>{_e(a['match_code'])}</span> · "
            f"{_e(t('apv.left', minutes=a['minutes_left']))}</small></a></li>" for a in items)
        body = f"<ul class=apvlist>{lis}</ul>"
    else:
        body = f"<p class=hint id=apvnone>{_e(t('apv.none'))}</p>"
    head = f"<style>{_APPROVAL_CSS}</style>"
    return _page(auth, t("apv.list_title"), f"<h1>{_e(t('apv.list_title'))}</h1>{body}", ctx=ctx,
                 current="approvals", head=head)


def _approval_stepup(auth, ctx, a) -> str:
    """The step-up of one approval: the fields of `stepup_options`, a passkey button, the provider button."""
    t = auth.t
    methods = list(ctx.get("methods") or [])
    parts = []
    secrets_ = [m for m in methods if m in ("totp", "pin", "password")]
    if secrets_:
        parts.append(f"<div class=or>{_e(t('or'))}</div>".join(
            _stepup_field(auth, m, i == 0) for i, m in enumerate(secrets_)))
    return "".join(parts)


_APPROVAL_PASSKEY_JS = """
<script>
document.getElementById('apvpk')?.addEventListener('click', async (ev) => {
  ev.preventDefault();
  const form = document.getElementById('apvform');
  try {
    const o = await (await fetch(form.getAttribute('action') + '/passkey', {method:'POST',
      headers:{'X-CSRF-Token':tsCsrf()}})).json();
    const dec = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0));
    o.challenge = dec(o.challenge);
    (o.allowCredentials||[]).forEach(c => c.id = dec(c.id));
    const cred = await navigator.credentials.get({publicKey:o});
    const enc = a => btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    document.getElementById('apvwa').value = JSON.stringify({id:cred.id, rawId:enc(cred.rawId), type:cred.type,
      response:{clientDataJSON:enc(cred.response.clientDataJSON), authenticatorData:enc(cred.response.authenticatorData),
      signature:enc(cred.response.signature), userHandle:cred.response.userHandle?enc(cred.response.userHandle):null}});
    document.getElementById('apvdec').name = 'decision';
    form.submit();
  } catch(e){ await tsAlert(__PK_ABORTED__+': '+e); }
});
</script>
"""


def _approval(auth, ctx) -> str:
    """ctx: outcome (open | done | rejected | closed | foreign), approval (view), methods, provider_ready, error.
    The approval page: who asks for what (from the operator's fixed texts and the database, every value escaped and
    bidi-isolated), the match code, the remaining time, the step-up of THIS approval, then Approve or Reject."""
    t = auth.t
    outcome = ctx.get("outcome") or "foreign"
    head = f"<style>{_APPROVAL_CSS}</style>"
    if outcome == "foreign":
        body = (f"<h1>{_e(t('apv.foreign_title'))}</h1><p class=hint id=apvforeign>{_e(t('apv.foreign'))}</p>")
        return _page(auth, t("apv.foreign_title"), body, ctx=ctx, head=head)
    a = ctx.get("approval") or {}
    table = f"<table class=qrinfo>{_approval_rows(a.get('rows') or [])}</table>"
    # A symbol AND a word, never colour alone: the warning triangle (inline SVG, nothing fetched; a font without the
    # ⚠ glyph would show a box) plus "Permanent", and the ⚠ character for screen readers and copy-paste.
    warn = (f"<div class=warnbar id=apvirrev><svg class=apvwarn viewBox='0 0 24 24' fill='none' stroke='currentColor' "
            f"stroke-width='2' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>{_SYMBOL['warn']}</svg>"
            f"<span class=apvwarntxt><span class=apvsr>⚠ </span>{_e(a.get('warning') or t('apv.irreversible'))}</span></div>"
            if a.get("irreversible") else "")
    summary = _approval_summary(a)
    title = f"<h1>{_e(a.get('title'))}</h1>"
    if a.get("app_action"):
        # Who asks, from the operator's register — above the title, so the person reads it first.
        title = f"<p class=apvmeta id=apvapp><bdi>{_e(a.get('app_name'))}</bdi></p>{title}"
    if outcome != "open":
        state = a.get("state") or ""
        if outcome == "done":
            kind, text = ("ok", t("apv.done_" + str(a.get("result") or "invalid")))
        elif outcome == "rejected":
            kind, text = ("info", t("apv.rejected"))
        else:
            kind, text = (_APV_STATE_KIND.get(state, "info"),
                          t("apv.state_" + state) if state else t("apv.closed"))
            if state == "consumed":
                text = t("apv.done_" + str(a.get("result") or "invalid"))
        msgs = _messages([("error", ctx.get("error")), (kind, text), ("info", t("apv.back"))])
        back = ""
        if a.get("return_to"):
            # Browser entry: a plain link back to the application's registered address (id and state, never the
            # confirmation) — a link, not a redirect: the GET of this page has no effect.
            back = (f"<p><a class=btn2 id=apvreturn href='{_e(a['return_to'])}'>"
                    f"{_e(t('apv.return', app=a.get('app_name') or ''))}</a></p>")
        body = (f"{title}{summary}{table}<p class=apvmeta id=apvstate data-state='{_e(state)}'>"
                f"<span class=apvstate>{_e(t('apv.state'))}: {_e(t('apv.st.' + state) if state else '—')}</span></p>"
                f"{back}")
        return _page(auth, str(a.get("title") or ""), body, ctx=ctx, head=head, below=msgs)
    methods = list(ctx.get("methods") or [])
    fields = _approval_stepup(auth, ctx, a)
    extra = ""
    if "passkey" in methods:
        extra += (f"<button type=button class=btn2 id=apvpk>{_e(t('apv.passkey'))}</button>"
                  + _csrf_js(auth) + ctx.get("dialog", "")
                  + _APPROVAL_PASSKEY_JS.replace("__PK_ABORTED__", json.dumps(t("apv.passkey_aborted"))))
    if "oidc" in methods:
        if ctx.get("provider_ready"):
            extra += f"<input type=hidden name=method value=oidc><p class=hint id=apvoidcok>✓ {_e(t('apv.oidc_ready'))}</p>"
        else:
            back = f"/auth/approvals/{a.get('id', '')}"
            extra += (f"<a class=btn2 id=apvoidc href='__TS_P__/auth/oidc/start?approval={_e(a.get('id', ''))}"
                      f"&amp;next={_next_q('__TS_P__' + back)}'>{_e(t('reauth.oidc', name=auth.cfg.oidc_name))}</a>")
    if "saml" in methods:          # T-99: the same at the SAML provider (`ForceAuthn`)
        if ctx.get("saml_ready"):
            extra += f"<input type=hidden name=method value=saml><p class=hint id=apvsamlok>✓ {_e(t('apv.oidc_ready'))}</p>"
        else:
            back = f"/auth/approvals/{a.get('id', '')}"
            extra += (f"<a class=btn2 id=apvsaml href='__TS_P__/auth/saml/login?approval={_e(a.get('id', ''))}"
                      f"&amp;next={_next_q('__TS_P__' + back)}'>{_e(t('reauth.oidc', name=auth.cfg.saml_name))}</a>")
    nothing ="" if methods else f"<div class=warnbar id=apvnomethod>{_e(t('apv.no_method'))}</div>"
    action = f"__TS_P__/auth/approvals/{_e(a.get('id', ''))}{_e(_app_q(ctx))}"
    body = (f"{title}{summary}{warn}{table}"
            f"<label>{_e(t('apv.code_question'))}</label><div class=apvcode id=apvcode>{_e(a.get('match_code'))}</div>"
            f"<p class=apvmeta id=apvvia>{_e(a.get('via'))} · {_e(t('apv.left', minutes=a.get('minutes_left', 0)))}</p>"
            f"<form method=post id=apvform action='{action}'>{_cf(ctx)}"
            f"<input type=hidden name=payload_hash value='{_e(a.get('payload_hash'))}'>"
            f"<input type=hidden name=webauthn id=apvwa value=''>"
            f"<input type=hidden id=apvdec value=approve>"
            f"<p class=hint>{_e(t('apv.stepup_hint'))}</p>{nothing}{fields}{extra}"
            f"<div class=apvbtns>"
            f"<button type=submit id=apvyes name=decision value=approve>{_e(t('apv.approve'))}</button>"
            f"<button type=submit id=apvno class=btn2 name=decision value=reject>{_e(t('apv.reject'))}</button>"
            f"</div></form>")
    msgs = _messages([("error", ctx.get("error"))])
    return _page(auth, str(a.get("title") or ""), body, ctx=ctx, head=head, below=msgs)


def _identity_sections(auth, ctx) -> list:
    """The account page's providers (T-99): the linked ones with "Unlink" — or, for the last way in, the reason instead
    of a button that refuses —, and the links SAML and LDAP offer. Every action is a POST with the CSRF token; the
    status is a symbol AND a word, never colour alone."""
    t = auth.t
    names = {"oidc": auth.cfg.oidc_name, "saml": auth.cfg.saml_name, "ldap": t("acc.ldap_name")}
    linked, offers = "", []
    for item in ctx.get("identities") or []:
        source = str(item.get("source") or "")
        name = names.get(source, source)
        if item.get("linked"):
            action = (f"<form method=post action='__TS_P__/auth/identities/unlink'>{_cf(ctx)}"
                      f"<input type=hidden name=source value='{_e(source)}'>"
                      f"<button type=submit class=warn>{_e(t('acc.identity_unlink', name=name))}</button></form>"
                      if item.get("can_unlink") else f"<p class='msg evhint'>{_e(t('acc.identity_last'))}</p>")
            linked += f"<li id=idl_{_e(source)}><span class=ok>✓ {_e(t('acc.identity_linked', name=name))}</span>{action}</li>"
        elif source == "saml":
            offers.append(
                f"<div class=sec><h2 id=link_saml>{_e(t('acc.oidc_link_title', name=name))}</h2>"
                f"<p class='msg evhint'>{_e(t('acc.oidc_link_hint', name=name))}</p>"
                f"<form method=post action='__TS_P__/auth/saml/link'>{_cf(ctx)}"
                f"<button type=submit>{_e(t('acc.oidc_link', name=name))}</button></form></div>")
        elif source == "ldap":
            offers.append(
                f"<div class=sec><h2 id=link_ldap>{_e(t('acc.ldap_link_title'))}</h2>"
                f"<p class='msg evhint'>{_e(t('acc.ldap_link_hint'))}</p>"
                f"<form method=post action='__TS_P__/auth/ldap/link'>{_cf(ctx)}"
                f"<label for=ldl_user>{_e(t('login.user'))}</label>"
                f"<input id=ldl_user name=username autocomplete=off required>"
                f"<label for=ldl_pw>{_e(t('login.password'))}</label>"
                f"<input id=ldl_pw name=password type=password autocomplete=off required>"
                f"<button type=submit>{_e(t('acc.ldap_link'))}</button></form></div>")
    head = (f"<div class=sec><h2 id=identities>{_e(t('acc.identities'))}</h2><ul id=idlist>{linked}</ul></div>"
            if linked else "")
    return ([head] if head else []) + offers


def _app_passwords_section(auth, ctx, u) -> str:
    """App passwords (T-66) on the account page: list (loaded by script), name, applications, lifetime, create.

    The applications are checkboxes and the first one is ticked: an app password is bound as narrowly as its
    use — one device, one application — unless the holder ticks more. The lifetime offers a month, a quarter, a
    year and the operator's default; "no expiry" only with `app_password_allow_unlimited`."""
    ap = ctx.get("app_passwords")
    if not ap or not ap.get("apps"):
        return ""
    t = auth.t
    apps = ""
    for i, app in enumerate(ap["apps"]):
        host = _e(app["host"])
        label = _e(app["name"]) + ("" if app["name"] == app["host"] else f" <small>({host})</small>")
        apps += (f"<label class=apapp><input type=checkbox name=ap_host value='{host}'"
                 f"{' checked' if i == 0 else ''}> {label}</label>")
    default = int(ap.get("default_days") or 365)
    choices = sorted({30, 90, 365, default})
    options = "".join(
        f"<option value={d}{' selected' if d == default else ''}>"
        f"{_e(t('acc.ap_year') if d == 365 else t('acc.ap_days', n=d))}</option>" for d in choices)
    if ap.get("allow_unlimited"):
        options += f"<option value=0>{_e(t('acc.ap_never_expires'))}</option>"
    return (f"<div class=sec id=apsec data-user='{_e(u['username'])}'><h2 id=app-passwords>{_e(t('acc.app_passwords'))}</h2>"
            f"<p class='msg evhint'>{_e(t('acc.app_passwords_hint'))}</p><ul id=aplist></ul>"
            f"<input id=ap_name maxlength=80 autocomplete=off placeholder='{_e(t('acc.ap_name'))}'>"
            f"<fieldset class=apapps><legend>{_e(t('acc.ap_for'))}</legend>{apps}</fieldset>"
            f"<label class=apdays>{_e(t('acc.ap_expires'))} <select id=ap_days>{options}</select></label>"
            f"<button data-act=mkap>{_e(t('acc.ap_create'))}</button><span id=ap_msg class=msg></span></div>")


def _devices_section(auth, ctx) -> str:
    """Connected programs (OAuth grants, T-36) on the account page — server-rendered, one form per device."""
    devices = ctx.get("oauth_devices")
    if devices is None:
        return ""
    import datetime as _dt
    t = auth.t

    def when(ts):
        return _dt.datetime.fromtimestamp(int(ts), _dt.timezone.utc).strftime("%Y-%m-%d %H:%M") + " UTC" if ts else "—"
    lines = "".join(
        f"<li><b>{_e(d['client_name'])}</b> <small><code>{_e(d['client_id'])}</code></small><br>"
        f"<small class=msg>{_e(t('acc.device_created'))} {_e(when(d['created_at']))} · "
        f"{_e(t('acc.device_last'))} {_e(when(d['last_used']))} · {_e(d['last_ip'] or '?')} · {_e(d['resource'])}"
        + (f" · <span class=devvia>{_e(t('acc.device_via_pairing'))}</span>" if d.get("via") == "pairing" else "")
        + "</small>"
        f"<form method=post class=devrevoke action='__TS_P__/auth/oauth/devices/{int(d['id'])}/revoke'>{_cf(ctx)}"
        f"<button type=submit class=warn>{_e(t('acc.device_revoke'))}</button></form></li>"
        for d in devices) or f"<li>{_e(t('acc.devices_none'))}</li>"
    return (f"<div class=sec><h2 id=devices>{_e(t('acc.devices'))}</h2>"
            f"<p class='msg evhint'>{_e(t('acc.devices_hint'))}</p><ul id=devlist>{lines}</ul></div>")


def _pairing_section(auth, ctx) -> str:
    """Pairing code for a program (ADR-14) on the account page: the consent given in advance for ONE following
    sign-in of a program such as Claude Code — fetched here, in the own session, redeemed by the setup script."""
    pairing = ctx.get("oauth_pairing")
    if not pairing:
        return ""
    t = auth.t
    resources = pairing.get("resources") or []
    choose = ""
    if len(resources) > 1:
        options = f"<option value=''>{_e(t('acc.pairing_any'))}</option>" + "".join(
            f"<option value='{_e(r)}'>{_e(name or r)}</option>" for r, name in resources)
        choose = f"<label class=apdays>{_e(t('acc.pairing_for'))} <select id=pc_res>{options}</select></label>"
    return (f"<div class=sec id=pcsec data-minutes='{int(pairing.get('minutes') or 0)}'>"
            f"<h2 id=pairing>{_e(t('acc.pairing'))}</h2>"
            f"<p class='msg evhint'>{_e(t('acc.pairing_hint', minutes=int(pairing.get('minutes') or 0)))}</p>"
            f"{choose}<button data-act=mkpc>{_e(t('acc.pairing_create'))}</button>"
            f"<span id=pc_msg class=msg></span></div>")


def _services_section(auth, ctx) -> str:
    """Services (T-60) on the account page: the list (loaded by script) and a pairing code for a new one. The
    applications are checkboxes, the first one ticked — a service is bound as narrowly as its use."""
    resources = ctx.get("service_resources")
    if not resources:
        return ""
    t = auth.t
    boxes = "".join(f"<label class=apapp><input type=checkbox name=sv_res value='{_e(r)}'"
                    f"{' checked' if i == 0 else ''}> {_e(r)}</label>" for i, r in enumerate(resources))
    return (f"<div class=sec id=svsec><h2 id=services>{_e(t('acc.services'))}</h2>"
            f"<p class='msg evhint'>{_e(t('acc.services_hint'))}</p><ul id=svlist></ul>"
            f"<input id=sv_name maxlength=80 autocomplete=off placeholder='{_e(t('acc.service_name'))}'>"
            f"<fieldset class=apapps><legend>{_e(t('acc.service_for'))}</legend>{boxes}</fieldset>"
            f"<button data-act=mksv>{_e(t('acc.service_pair'))}</button><span id=sv_msg class=msg></span></div>")


# Passkey login JS (WebAuthn) — only included when passkey is active.
_PASSKEY_LOGIN_JS = """
<script>
document.getElementById('pkbtn')?.addEventListener('click', async () => {
  try {
    const o = await (await fetch('__TS_P__/auth/passkey/login/begin', {method:'POST',headers:{'X-CSRF-Token':tsCsrf()}})).json();
    o.challenge = Uint8Array.from(atob(o.challenge.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0));
    (o.allowCredentials||[]).forEach(c => c.id = Uint8Array.from(atob(c.id.replace(/-/g,'+').replace(/_/g,'/')), x=>x.charCodeAt(0)));
    const cred = await navigator.credentials.get({publicKey:o});
    const enc = a => btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    const payload = {id:cred.id, rawId:enc(cred.rawId), type:cred.type, response:{
      clientDataJSON:enc(cred.response.clientDataJSON), authenticatorData:enc(cred.response.authenticatorData),
      signature:enc(cred.response.signature), userHandle:cred.response.userHandle?enc(cred.response.userHandle):null}};
    const r = await fetch('__TS_P__/auth/passkey/login/finish?next=__NEXT__', {method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},body:JSON.stringify(payload)});
    if (r.ok) location.href = (await r.json()).redirect || '__TS_P__/'; else await tsAlert(__PK_FAILED__);
  } catch(e){ await tsAlert(__PK_ABORTED__+': '+e); }
});
</script>
"""


def _area(auth, ctx) -> str:
    """The TinySesam area of an application (T-104) — built in `_area.py`."""
    from . import _area as _area_page
    return _area_page.page(auth, ctx)


DEFAULTS = {
    "logout": _logout,
    "gate_logout": _gate_logout,
    "gate_logged_out": _gate_logged_out,
    "gateway_home": _gateway_home,
    "login": _login,
    "totp": _totp,
    "reauth": _reauth,
    "pin": _pin,
    "resource_unlock": _resource_unlock,
    "account": _account,
    "area": _area,
    "register": _register,
    "magic_request": _magic_request,
    "magic_invalid": _magic_invalid,
    "magic_confirm": _magic_confirm,
    "qr_login": _qr_login,
    "qr_approve": _qr_approve,
    "error": _error,
    "forgot": _forgot,
    "reset": _reset,
    "totp_setup": _totp_setup,
    "account_setup": _account_setup,
    "oauth_consent": _oauth_consent,
    "oauth_return": _oauth_return,
    "approvals": _approvals,
    "approval": _approval,
}

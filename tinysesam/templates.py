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

from .theme import TOKENS

_NONCE_TAG = re.compile(r'<(script|style)(?![^>]*\bnonce=)(?=[\s>])')


def inject_nonce(html_str: str, nonce: str) -> str:
    """Give every `<script>`/`<style>` without its own nonce the response's nonce (CSP 'strict').

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

    def ueberschrieben(self, name: str) -> bool:
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
PRAEFIX_PLATZHALTER = "__TS_P__"

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
.tsmain .warnbar{background:var(--ts-warn-bg);color:var(--ts-warn-ink);padding:9px 12px;
     border-radius:8px;font-size:12px;margin-bottom:10px}
/* Messages (PO 2026-10-08): a box of their own BELOW the card, one icon per message. Notice, warning and
   error are built alike and differ only in colour and icon. */
.tsmain .meldungen{width:340px;max-width:92vw;display:flex;flex-direction:column;gap:8px}
.tsmain .meldung{display:flex;align-items:flex-start;gap:10px;padding:11px 14px;font-size:13px;line-height:1.4;
     border-radius:calc(var(--ts-radius) + 2px);border:1px solid var(--ts-line)}
.tsmain .meldung svg{flex:0 0 18px;width:18px;height:18px;margin-top:1px}
.tsmain .meldung.info{background:var(--ts-info-bg);color:var(--ts-info-ink)}
.tsmain .meldung.warn{background:var(--ts-warn-bg);color:var(--ts-warn-ink)}
.tsmain .meldung.fehler{background:var(--ts-err-bg);color:var(--ts-err-ink)}
.tsmain .meldung.ok{background:var(--ts-ok-bg);color:var(--ts-ok-ink)}
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


#: Built-in favicon (since 0.24.8): a plain key, switching light/dark — as a data: URI, so without
#: a fetch. Without a favicon the browser requests /favicon.ico; behind a gate that is a protected path.
STANDARD_FAVICON = "data:image/svg+xml;base64," + __import__("base64").b64encode(
    b"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><style>path,circle{stroke:#111}"
    b"@media(prefers-color-scheme:dark){path,circle{stroke:#eee}}</style><g fill='none' stroke-width='3' "
    b"stroke-linecap='round'><circle cx='11' cy='16' r='6'/><path d='M17 16h12M24 16v5M28 16v4'/></g></svg>").decode()


def favicon_link(icon: str) -> str:
    """Favicon `<link>` for the built-in pages. One place, so no page forgets it. Empty = the built-in
    default icon, "none" = none."""
    if icon == "none":
        return ""
    return f"<link rel=icon href='{html.escape(icon or STANDARD_FAVICON)}'>"


def hintergrund(cfg) -> tuple[str, str]:
    """(CSS, HTML) of the rotating background images from `brand_backgrounds` — empty if none are set. The image
    sits in the (nonce-protected) page `<style>`, not in style=: the strict CSP forbids inline attributes."""
    bilder = [b for b in (getattr(cfg, "brand_backgrounds", None) or []) if b]
    if not bilder:
        return "", ""
    # f = cross-fade time between two images. All delays are pulled forward by (f − 0.5 s): the first image appears after
    # half a second, instead of emerging from black only after f seconds (PO 2026-10-09).
    n, d, f = len(bilder), int(getattr(cfg, "brand_background_seconds", 12) or 12), 3
    t = n * d
    css = [".tsbg{position:fixed;inset:0;z-index:-1;background:var(--ts-image-base);overflow:hidden}",
           (".tsbg i{position:absolute;inset:-2%;background:center/cover no-repeat;opacity:0;"
            "filter:grayscale(.25) brightness(var(--ts-image-brightness))}"),
           (".tsbg::after{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at center,"
            "var(--ts-image-overlay),var(--ts-image-overlay-edge))}"),
           "body{background:transparent}",
           (".tsbg-quelle{position:fixed;right:12px;bottom:8px;font-size:11px;color:var(--ts-muted);opacity:.55;"
            "text-decoration:none}.tsbg-quelle:hover{opacity:.9;text-decoration:underline}")]
    if n == 1:
        css.append(".tsbg i{opacity:var(--ts-image-strength)}")
    else:
        a, b, c = f / t * 100, d / t * 100, (d + f) / t * 100
        css.append(f"@keyframes tsbg{{0%{{opacity:0}}{a:.3f}%{{opacity:var(--ts-image-strength)}}"
                   f"{b:.3f}%{{opacity:var(--ts-image-strength)}}"
                   f"{c:.3f}%{{opacity:0}}100%{{opacity:0}}}}")
        css.append(f".tsbg i{{animation:tsbg {t}s linear infinite}}")
        css.append("@media(prefers-reduced-motion:reduce){.tsbg i{animation:none}.tsbg i:first-child{opacity:var(--ts-image-strength)}}")
    for k, b in enumerate(bilder, 1):
        css.append(f".tsbg i:nth-child({k}){{background-image:url('{b}')"
                   + (f";animation-delay:{(k - 1) * d - (f - 0.5):g}s" if n > 1 else "") + "}")
    quelle = ""
    text, ziel = getattr(cfg, "brand_background_credit_text", ""), getattr(cfg, "brand_background_credit_url", "")
    if text:
        quelle = (f"<a class=tsbg-quelle href='{html.escape(ziel)}' target=_blank rel='noopener noreferrer'>"
                  f"{html.escape(text)}</a>" if ziel else f"<span class=tsbg-quelle>{html.escape(text)}</span>")
    return "".join(css), "<div class=tsbg aria-hidden=true>" + "<i></i>" * n + "</div>" + quelle


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
         header="", footer="", unten="", hg=("", ""), kopf=""):
    """`top` sits outside the card (e.g. the demo notice) — directly above it, same width; `unten` directly
    below it (the messages). `header`/`footer` enclose the page so the host app can put its navigation
    around it. `kopf` lands in `<head>` before the branding (e.g. a meta refresh)."""
    inner = (f"<div class=card>{body}</div>" if card else body) + (unten or "")
    return (f"<!doctype html><html lang={html.escape(lang)}><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"{favicon_link(brand_icon)}{kopf}"
            f"<title>{html.escape(title)}</title><style>{_CSS}{hg[0]}{brand_css or ''}</style>{brand_head or ''}</head>"
            f"<body>{hg[1]}{header}<div class=tsmain>{top}{inner}</div>{footer}</body></html>")


def _shell(title, body, lang="en"):
    return _doc(title, body)


def _page(auth, title, body, card=True, top="", unten="", kopf=""):
    """Like _shell, but with branding from the config (brand_css/brand_head/brand_icon/brand_header/
    brand_footer) — re-skins and frames all pages centrally. `top` lands above the card, `unten` below it."""
    cfg = auth.cfg
    return _doc(title, body, cfg.lang, getattr(cfg, "brand_css", ""), getattr(cfg, "brand_head", ""),
                card, getattr(cfg, "brand_icon", ""), top,
                brand(getattr(cfg, "brand_header", ""), auth), brand(getattr(cfg, "brand_footer", ""), auth), unten,
                hintergrund(cfg), kopf)


#: Message icons — inline SVG in currentColor (nothing is fetched), 24 grid, strokes only.
_SYMBOL = {
    "info": "<circle cx='12' cy='12' r='9'/><path d='M12 11v5'/><path d='M12 7.5v.5'/>",
    "warn": "<path d='M12 3.5 21 19.5H3z'/><path d='M12 10v4'/><path d='M12 16.5v.5'/>",
    "fehler": "<circle cx='12' cy='12' r='9'/><path d='M8.5 8.5l7 7'/><path d='M15.5 8.5l-7 7'/>",
    "ok": "<circle cx='12' cy='12' r='9'/><path d='M8 12.5l2.8 2.8L16 10'/>",
}


def _meldungen(liste) -> str:
    """Messages as a separate box below the card: `[(art, text), …]`, art ∈ info | ok | warn | fehler.
    Empty texts are dropped; without a message there is no box."""
    teile = []
    for art, text in liste:
        if not text:
            continue
        art = art if art in _SYMBOL else "info"
        rolle = "alert" if art == "fehler" else "status"
        teile.append(f"<div class='meldung {art}' role={rolle}>"
                     f"<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' "
                     f"stroke-linejoin='round' aria-hidden='true'>{_SYMBOL[art]}</svg><span>{_e(text)}</span></div>")
    return f"<div class=meldungen>{''.join(teile)}</div>" if teile else ""


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
  addEventListener('pageshow', function(e){ if(e.persisted) clear(); });   // Zurueck-Taste
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
    meldungen = _meldungen([("info", ctx.get("info")), ("warn", ctx.get("warn")), ("fehler", error)])
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
    if "magic" in methods:
        magic = f"<a class=btn2 href='__TS_P__/auth/magic/request?next={_next_q(next_)}'>{_e(t('login.magic'))}</a>"
    # `app` (T-14) travels along: without it the button would start the round with the default client,
    # and the approval for THIS application would never come about (B-2).
    app_q = f"&app={_e(_quote(ctx['app']))}" if ctx.get("app") else ""
    oidc = (f"<a class=btn2 href='__TS_P__/auth/oidc/start?next={_next_q(next_)}{app_q}'>{_e(cfg.oidc_name)}</a>"
            if "oidc" in methods else "")
    saml = (f"<a class=btn2 href='__TS_P__/auth/saml/login?next={_next_q(next_)}'>{_e(cfg.saml_name)}</a>"
            if "saml" in methods else "")
    passkey = f"<button class=btn2 type=button id=pkbtn>{_e(t('login.passkey'))}</button>" if "passkey" in methods else ""
    others = oidc + saml + passkey + magic
    sep = _or if others and (pw or pin) else ""
    links = []
    if cfg.allow_signup:
        links.append(f"<a href='__TS_P__/auth/register?next={_next_q(next_)}'>{_e(t('login.signup'))}</a>")
    if getattr(cfg, "password_reset_enabled", False) and cfg.magiclink_enabled:
        links.append(f"<a href='__TS_P__/auth/forgot'>{_e(t('login.forgot'))}</a>")
    signup = f"<div class=hint>{' · '.join(links)}</div>" if links else ""
    js = (_csrf_js(auth) + _PASSKEY_LOGIN_JS.replace("__NEXT__", _next_q(next_))) if "passkey" in methods else ""
    # In front of an application (forward_apps[host].name, T-21) the page says what you sign in for. With a brand
    # (gate_brand) the brand stands on top and the application as its own line below.
    marke = getattr(cfg, "gate_brand", "") or ""
    if marke:
        titel = t("login.for_app", name=marke)
    else:
        titel = t("login.for_app", name=ctx["app_name"]) if ctx.get("app_name") else cfg.rp_name
    app_zeile = (f"<p class=app>{_e(t('login.app_line', name=ctx['app_name']))}</p>"
                 if marke and ctx.get("app_name") else "")
    # Signed out of this application only (T-22): back in with one click, without a new sign-in.
    weiter = ""
    if ctx.get("resume_user"):
        gh = f"<input type=hidden name=gate_host value='{_e(ctx['gate_host'])}'>" if ctx.get("gate_host") else ""
        weiter = (f"<form method=post action='__TS_P__/auth/gate/resume'>"
                  f"<input type=hidden name=next value='{_e(next_)}'>{gh}{_cf(ctx)}"
                  f"<button type=submit>{_e(t('gate.resume', name=ctx['resume_user']))}</button></form>"
                  + (_or if (pw or pin or others) else ""))
    body = f"<h1>{_e(titel)}</h1>{app_zeile}{weiter}{pw}{pin}{sep}{others}{signup}{js}"
    seitentitel = t("login.brand_title", name=marke) if marke else t("login.submit")
    return _page(auth, seitentitel, body, top=_demobar(auth, ctx=ctx), unten=meldungen)


def _totp(auth, ctx) -> str:
    """ctx: next, error."""
    t = auth.t
    meldungen = _meldungen([("fehler", ctx.get("error"))])
    body = (f"<h1>{_e(t('totp.title'))}</h1>"
            f"<form method=post action='__TS_P__/auth/totp'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"<label>{_e(t('totp.label'))}</label>"
            f"<input name=code class=code inputmode=numeric autocomplete=one-time-code autofocus maxlength=6>"
            f"<button type=submit>{_e(t('totp.submit'))}</button></form>"
            f"<div class=hint><a href='__TS_P__/auth/logout'>{_e(t('cancel'))}</a></div>")
    return _page(auth, t("totp.title"), body, unten=meldungen)


def _account(auth, ctx) -> str:
    """ctx: user, methods, has_totp, has_pin, is_admin, admin_path, events. Self-service + logout.
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
        aktuell = u.get("email") or ""
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.email'))}</h2>"
            + (f"<div class=msg>{_e(aktuell)}</div>" if aktuell else "")
            + f"<input id=mail_new type=email autocomplete=email placeholder='{_e(t('acc.email_new'))}'>"
            f"<button data-act=setmail>{_e(t('acc.email_change'))}</button><span id=mail_msg class=msg></span></div>")

    # Change password
    if "password" in methods:
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
            rest = ctx.get("recovery_left")
            hinweis = ""
            if rest is not None:
                knapp = rest <= ctx.get("recovery_warn", 3)
                hinweis = (f" <small class={'err' if knapp else 'ok'} id=rc_left>"
                           f"{_e(t('acc.recovery_low' if knapp else 'acc.recovery_left', n=rest))}</small>")
            totp = (f"<span class=ok>{_e(t('acc.totp_active'))}</span> "
                    f"<button class=warn data-act=deltotp>{_e(t('acc.totp_off'))}</button> "
                    f"<button data-act=recovery>{_e(t('acc.recovery'))}</button>{hinweis}")
        else:
            totp = f"<a class=btnlink href='__TS_P__/auth/totp/setup'>{_e(t('acc.totp_setup'))}</a>"
        sections.append(f"<div class=sec><h2>{_e(t('acc.totp'))}</h2>{totp}<span id=totp_msg class=msg></span>"
                        "<pre id=rc_out class=rcout></pre></div>")

    # Passkeys
    if "passkey" in methods:
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.passkeys'))}</h2><ul id=pklist></ul>"
            f"<button data-act=addpk>{_e(t('acc.passkey_add'))}</button><span id=pk_msg class=msg></span></div>")

    # API keys
    if auth.cfg.apikey_enabled:
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.keys'))}</h2><ul id=keylist></ul>"
            f"<input id=key_name placeholder='{_e(t('acc.key_name'))}'>"
            f"<button data-act=mkkey>{_e(t('acc.key_create'))}</button><span id=key_msg class=msg></span></div>")

    # Active sessions (always)
    sections.append(
        f"<div class=sec><h2>{_e(t('acc.sessions'))}</h2><ul id=sesslist></ul>"
        f"<button class=warn data-act=revokeothers>{_e(t('acc.sessions_revoke'))}</button>"
        "<span id=sess_msg class=msg></span></div>")

    # Own events (H-7): whoever sees that a sign-in happened at 3 a.m. from a foreign address
    # speaks up — the log so far lay only with the operator. Rendered
    # server-side (no further endpoint), time as UTC, because the page does not know the
    # reader's zone. `events` missing in the ctx of a custom template/preview → section omitted.
    # The spacing comes from a class in the page `<style>`, not from `style=`: the strict CSP
    # allows styles only via nonce, and that does not apply to attributes (integration finding 9).
    events = ctx.get("events")
    if events is not None:
        import datetime as _dt
        zeilen = "".join(
            f"<li><code>{_e(_dt.datetime.fromtimestamp(int(ev['ts']), _dt.timezone.utc).strftime('%Y-%m-%d %H:%M'))}"
            f" UTC</code> {_e(ev['event'])} <small>"
            f"{_e(t('acc.events_by_admin') if ev.get('by_admin') else (ev.get('ip') or ''))}</small></li>"
            for ev in events) or f"<li>{_e(t('acc.events_none'))}</li>"
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.events'))}</h2>"
            f"<p class='msg evhint'>{_e(t('acc.events_hint'))}</p>"
            f"<ul id=eventlist>{zeilen}</ul></div>")

    admin_link = (f"<a href='{_e('__TS_P__' + ctx.get('admin_path', '/auth/admin'))}'>{_e(t('acc.admin'))}</a>"
                  if ctx.get("is_admin") else "")

    css = """
    .tsmain{max-width:640px;margin:0 auto;padding:24px;display:block}
    .tsmain header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
    .tsmain header h1{font-size:20px;margin:0}
    .tsmain .sec{background:var(--ts-surface);border:1px solid var(--ts-line);
         border-radius:var(--ts-radius);padding:16px;margin-bottom:14px}
    .tsmain .sec h2{font-size:13px;color:var(--ts-muted);text-transform:uppercase;
         letter-spacing:.05em;margin:0 0 12px}
    .tsmain .sec small{text-transform:none;letter-spacing:0}
    .tsmain .sec input{margin:4px 0}
    .tsmain .sec button,.tsmain .btnlink{width:auto;display:inline-block;margin:8px 6px 0 0;padding:9px 14px}
    .tsmain button.warn{background:var(--ts-danger)}
    .tsmain .btnlink{background:var(--ts-neutral);color:var(--ts-neutral-ink);border-radius:8px;
         text-decoration:none;padding:9px 14px}
    .tsmain .msg{margin-left:8px;font-size:12px;color:var(--ts-muted)}
    .tsmain .msg.evhint{margin:0 0 8px}
    .tsmain .msg.good,.tsmain .ok{color:var(--ts-ok-ink);background:none;padding:0}
    .tsmain .msg.bad,.tsmain .bad{color:var(--ts-err-ink)}
    .tsmain ul{list-style:none;padding:0;margin:0 0 8px}
    .tsmain li{padding:4px 0;font-size:13px;border-bottom:1px solid var(--ts-line-soft)}
    .tsmain a{color:var(--ts-link)}
    .tsmain .rcout{white-space:pre-wrap;margin-top:10px}
    """
    # `static=True`: only show the page, fetch nothing (preview/screenshot).
    static = bool(ctx.get("static"))
    pkjs = "" if static else (_PASSKEY_REGISTER_JS if "passkey" in methods else "")
    body = (f"<header><h1>{_e(t('acc.title'))} · {name}</h1>"
            f"<div>{admin_link} <a href='__TS_P__/auth/logout'>{_e(t('logout'))}</a></div></header>"
            + "".join(sections)
            + ("" if static else _ACCOUNT_JS.replace("__CSRFCK__", _e(auth.csrf_cookie_name)).replace("__TXT__", _account_texts(auth))
               + _revoke_js(auth, "location.pathname+'?revoke_others=1'") + _ACCOUNT_RUECKKEHR_JS
               .replace("__CONFIRM__", json.dumps(t("acc.sessions_confirm"))))
            + pkjs)
    # Account uses full width (no card) + account CSS + branding
    return _page(auth, t("acc.title"), f"<style>{css}</style>{body}", card=False)


#: Texts of the account page's JavaScript (no keys in `messages.py` yet — they are chosen by
#: `config.lang`, fallback "en"; the "de" column is the earlier German wording).
_ACCOUNT_TEXT = {
    "en": {
        "locale": "en-GB", "error": "Error", "mail_sent": "Link sent — please confirm it in the new mailbox",
        "changed": "✓ changed", "set": "✓ set", "removed": "✓ removed",
        "confirm_2fa_off": "Really disable 2FA?",
        "confirm_recovery": "Generate new recovery codes? The old ones become invalid.",
        "recovery_note": "Write these down safely now (visible only once):",
        "revoked": "(revoked)", "revoke": "revoke", "none": "none", "delete": "delete", "this": "(this one)",
        "key_copy": "API key — copy it NOW:", "confirm_end_others": "End all other sessions?",
        "ended": "✓ ended", "added": "✓ added", "failed": "failed", "aborted": "aborted: ",
    },
    "de": {
        "locale": "de-DE", "error": "Fehler", "mail_sent": "Link verschickt — bitte in der neuen Adresse bestätigen",
        "changed": "✓ geändert", "set": "✓ gesetzt", "removed": "✓ entfernt",
        "confirm_2fa_off": "2FA wirklich deaktivieren?",
        "confirm_recovery": "Neue Recovery-Codes erzeugen? Alte werden ungültig.",
        "recovery_note": "Jetzt sicher notieren (einmalig sichtbar):",
        "revoked": "(widerrufen)", "revoke": "widerrufen", "none": "keine", "delete": "löschen", "this": "(diese)",
        "key_copy": "API-Key — JETZT kopieren:", "confirm_end_others": "Alle anderen Sitzungen beenden?",
        "ended": "✓ beendet", "added": "✓ hinzugefügt", "failed": "fehlgeschlagen", "aborted": "abgebrochen: ",
    },
}


def _account_texts(auth) -> str:
    """The account page's JS texts as a JSON literal (ASCII-escaped, so it is safe inside `<script>`)."""
    return json.dumps(_ACCOUNT_TEXT.get(auth.cfg.lang) or _ACCOUNT_TEXT["en"])


_ACCOUNT_JS = """
<script>
function tsCsrf(){return (document.cookie.match(/(?:^|; )__CSRFCK__=([^;]+)/)||[])[1]||''}
const TXT=__TXT__;
async function J(u,b){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},body:JSON.stringify(b||{})});
  // 403 + X-TinySesam-Reauth: factor management has required a fresh confirmation since R3-3.
  // Without this switch the button failed silently once the freshness had expired.
  const re=r.headers.get('X-TinySesam-Reauth');
  if(r.status===403&&re){location.href=re+'?next='+encodeURIComponent(location.pathname);return r}
  return r}
const say=(id,t,good)=>{const e=document.getElementById(id);if(e){e.textContent=t;e.className='msg '+(good?'good':'bad')}};
async function setname(){const r=await J('__TS_P__/auth/account/username',{username:un_new.value});
  const j=await r.json().catch(()=>({}));say('un_msg',r.ok?'✓':(j.detail||TXT.error),r.ok)}
async function setmail(){const r=await J('__TS_P__/auth/account/email',{email:mail_new.value});
  const j=await r.json().catch(()=>({}));say('mail_msg',r.ok?'✓ '+TXT.mail_sent:(j.detail||TXT.error),r.ok);if(r.ok)mail_new.value=''}
async function changepw(){const r=await J('__TS_P__/auth/password',{current:pw_cur.value,new:pw_new.value});
  say('pw_msg',r.ok?TXT.changed:(await r.json()).detail||TXT.error,r.ok);if(r.ok){pw_cur.value='';pw_new.value=''}}
async function setpin(){const r=await J('__TS_P__/auth/pin/set',{pin:pin_new.value});await offer(r);
  say('pin_msg',r.ok?TXT.set:(await r.json()).detail||TXT.error,r.ok);if(r.ok)setTimeout(()=>location.reload(),600)}
// Check first, then report: both buttons used to say "done" UNCONDITIONALLY and reload —
// even on 403 (expired step-up freshness, missing CSRF token) or 500. The user saw
// "removed", the factor was still there.
async function delpin(){const r=await J('__TS_P__/auth/pin/disable');await offer(r);
  say('pin_msg',r.ok?TXT.removed:(await r.json().catch(()=>({}))).detail||TXT.error,r.ok);
  if(r.ok)setTimeout(()=>location.reload(),600)}
async function deltotp(){if(!confirm(TXT.confirm_2fa_off))return;
  const r=await J('__TS_P__/auth/totp/disable');await offer(r);
  if(r.ok)location.reload();else say('totp_msg',(await r.json().catch(()=>({}))).detail||TXT.error,false)}
async function recovery(){if(!confirm(TXT.confirm_recovery))return;
  const r=await (await J('__TS_P__/auth/totp/recovery')).json();
  if(r.codes){document.getElementById('rc_out').textContent=TXT.recovery_note+'\\n'+r.codes.join('\\n')}else say('totp_msg',r.detail||TXT.error,false)}
async function loadkeys(){const el=document.getElementById('keylist');if(!el)return;
  const ks=await (await fetch('__TS_P__/auth/apikeys')).json().catch(()=>[]);
  if(!Array.isArray(ks)){el.innerHTML='<li>—</li>';return}
  el.innerHTML=ks.map(k=>`<li>${esc0(k.prefix)} ${esc0(k.name)} ${k.revoked?'<span class=bad>'+TXT.revoked+'</span>':`<button class=warn data-act=revk data-id="${esc0(k.id)}">${TXT.revoke}</button>`}</li>`).join('')||'<li>'+TXT.none+'</li>'}
async function mkkey(){const r=await (await J('__TS_P__/auth/apikeys',{name:key_name.value})).json();
  if(r.key)prompt(TXT.key_copy,r.key);loadkeys()}
async function revk(id){await J('__TS_P__/auth/apikeys/'+id+'/revoke');loadkeys()}
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
async function revokeothers(){if(!confirm(TXT.confirm_end_others))return;
  if(await tsRevokeOthers())say('sess_msg',TXT.ended,true);loadsess()}
// One delegated listener instead of inline click handlers — otherwise the strict CSP
// blocks the buttons. The buttons loaded later via JS (data-act=revk/delpk) are reached as well.
document.addEventListener('click',function(e){var b=e.target.closest('[data-act]');if(!b)return;
  var f=window[b.dataset.act];if(typeof f==='function'){e.preventDefault();f(b.dataset.id)}});
loadkeys();loadpk();loadsess();
</script>
"""

_PASSKEY_REGISTER_JS = """
<script>
async function addpk(){
  try{
    const o=await (await fetch('__TS_P__/auth/passkey/register/begin',{method:'POST',headers:{'X-CSRF-Token':tsCsrf()}})).json();
    o.challenge=Uint8Array.from(atob(o.challenge.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    o.user.id=Uint8Array.from(atob(o.user.id.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    (o.excludeCredentials||[]).forEach(c=>c.id=Uint8Array.from(atob(c.id.replace(/-/g,'+').replace(/_/g,'/')),x=>x.charCodeAt(0)));
    const cred=await navigator.credentials.create({publicKey:o});
    const enc=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    const payload={id:cred.id,rawId:enc(cred.rawId),type:cred.type,response:{
      clientDataJSON:enc(cred.response.clientDataJSON),attestationObject:enc(cred.response.attestationObject),
      transports:(cred.response.getTransports&&cred.response.getTransports())||[]}};
    const r=await fetch('__TS_P__/auth/passkey/register/finish',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},body:JSON.stringify(payload)});
    say('pk_msg',r.ok?TXT.added:TXT.failed,r.ok);loadpk();await offer(r);loadsess();
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
        return _page(auth, t("reg.verify_title"), body, unten=_meldungen([("ok", t("reg.verify"))]))
    cfg = auth.cfg
    meldungen = _meldungen([("fehler", ctx.get("error"))])
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
    return _page(auth, t("reg.title"), body, unten=meldungen)


def _magic_request(auth, ctx) -> str:
    """ctx: next, sent (bool), error. E-mail address for the login link."""
    t = auth.t
    if ctx.get("sent"):
        body = (f"<h1>{_e(t('magic.sent_title'))}</h1>"
                f"<div class=hint>{_e(t('magic.sent_hint'))}</div>"
                f"<a class=btn2 href='__TS_P__/auth/login'>{_e(t('magic.back_login'))}</a>")
        return _page(auth, t("magic.sent_title"), body, unten=_meldungen([("ok", t("magic.sent"))]))
    meldungen = _meldungen([("fehler", ctx.get("error"))])
    body = (f"<h1>{_e(t('magic.title'))}</h1>"
            f"<div class=hint>{_e(t('magic.hint'))}</div>"
            f"<form method=post action='__TS_P__/auth/magic/request'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"<label>{_e(t('magic.email'))}</label>"
            f"<input name=email type=email autocomplete=email autofocus>"
            f"<button type=submit>{_e(t('magic.send'))}</button></form>"
            f"<div class=hint><a href='__TS_P__/auth/login'>{_e(t('back'))}</a></div>")
    return _page(auth, t("magic.title"), body, unten=meldungen)


def _forgot(auth, ctx) -> str:
    """ctx: sent (bool), error. E-mail for the reset link."""
    t = auth.t
    if ctx.get("sent"):
        return _page(auth, t("magic.sent_title"),
                      f"<h1>{_e(t('magic.sent_title'))}</h1>"
                      f"<a class=btn2 href='__TS_P__/auth/login'>{_e(t('magic.to_login'))}</a>",
                      unten=_meldungen([("ok", t("magic.sent"))]))
    meldungen = _meldungen([("fehler", ctx.get("error"))])
    body = (f"<h1>{_e(t('forgot.title'))}</h1>"
            f"<div class=hint>{_e(t('forgot.hint'))}</div>"
            f"<form method=post action='__TS_P__/auth/forgot'>{_cf(ctx)}"
            f"<label>{_e(t('magic.email'))}</label><input name=email type=email autocomplete=email autofocus>"
            f"<button type=submit>{_e(t('forgot.send'))}</button></form>"
            f"<div class=hint><a href='__TS_P__/auth/login'>{_e(t('back'))}</a></div>")
    return _page(auth, t("forgot.title"), body, unten=meldungen)


def _reset(auth, ctx) -> str:
    """ctx: token, error. Set a new password."""
    t = auth.t
    meldungen = _meldungen([("fehler", ctx.get("error"))])
    body = (f"<h1>{_e(t('reset.title'))}</h1>"
            f"<form method=post action='__TS_P__/auth/reset'>"
            f"<input type=hidden name=token value='{_e(ctx.get('token', ''))}'>{_cf(ctx)}"
            f"<label>{_e(t('reset.new'))}</label>"
            f"<input name=password type=password autocomplete=new-password autofocus>"
            f"<button type=submit>{_e(t('reset.submit'))}</button></form>")
    return _page(auth, t("reset.title"), body, unten=meldungen)


def _error(auth, ctx) -> str:
    """ctx: code, message. Themed error page (403/404/429/500 …). Replaceable via set_template('error')."""
    t = auth.t
    code = ctx.get("code", 500)
    msg = ctx.get("message") or t("error.oops")
    body = (f"<h1 class=errcode>{_e(code)}</h1>"
            f"<div class='hint errhint'>{_e(msg)}</div>"
            f"<a class=btn2 href='__TS_P__/'>{_e(t('error.home'))}</a>")
    return _page(auth, str(code), body)


def _magic_confirm(auth, ctx) -> str:
    """ctx: purpose ('login'|'verify_email'|'email_change'), action. A button that redeems the
    one-time link (R4-02).

    The link from the mail no longer redeems on GET — mail scanners open every link and
    would otherwise have consumed it. Only this POST (with CSRF token) does it."""
    t = auth.t
    knopf = {"verify_email": t("magic.confirm_verify"),
             "email_change": t("magic.confirm_email_change")}.get(ctx.get("purpose"), t("magic.confirm_login"))
    body = (f"<h1>{_e(t('magic.confirm_title'))}</h1>"
            f"<div class=hint>{_e(t('magic.confirm_hint'))}</div>"
            f"<form method=post action='{_e(ctx.get('action', ''))}'>{_cf(ctx)}"
            f"<button type=submit autofocus>{_e(knopf)}</button></form>")
    return _page(auth, t("magic.confirm_title"), body)


def _revoke_js(auth, zurueck: str) -> str:
    """JS for the offer after a factor change (B1-7, ASVS 7.4.3): `offer(r)` reads
    `other_sessions` from the response and asks, `tsRevokeOthers()` ends the remaining
    sessions. Needs `tsCsrf()` on the page.

    Ending requires a fresh confirmation (F-09), creating a factor does not always
    (passkey, TOTP need only a session). If the freshness has expired, the path leads through
    the reauth page — and `zurueck` (a JS expression, or empty) says where to go afterwards,
    so that the consent already given is not silently lost (A-5). During
    this redirect `tsRevokeOthers` never returns: a caller that reloads afterwards
    would otherwise abort the navigation."""
    t = auth.t
    ziel = (f"location.href=re+'?next='+encodeURIComponent({zurueck});return new Promise(()=>{{}})"
            if zurueck else f"alert({json.dumps(t('api.stepup'))});return false")
    return ("<script>"
            "async function tsRevokeOthers(){const r=await fetch('__TS_P__/auth/sessions/revoke',{method:'POST',"
            "headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},"
            "body:JSON.stringify({scope:'others'})});"
            "const re=r.headers.get('X-TinySesam-Reauth');"
            f"if(r.status===403&&re){{{ziel}}}return r.ok}}"
            "async function offer(r){let j={};try{j=await r.clone().json()}catch(e){}"
            f"if(r.ok&&j.other_sessions>0&&confirm({json.dumps(t('acc.sessions_offer'))}))"
            "await tsRevokeOthers();"
            # Boundary d: in the middle of the chain — note it, redeemed at the end.
            f"if(r.ok&&j.other_sessions_after>0&&confirm({json.dumps(t('acc.sessions_offer'))}))"
            "await fetch('__TS_P__/auth/sessions/revoke-after-login',{method:'POST',"
            "headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},body:'{}'})}</script>")


# Back from reauth with `?revoke_others=1`: ask once more, then end. Not silently
# executed — otherwise every foreign link to this address would end the other sessions.
_ACCOUNT_RUECKKEHR_JS = """<script>
if(new URLSearchParams(location.search).get('revoke_others')==='1'){
  history.replaceState(null,'',location.pathname);
  if(confirm(__CONFIRM__))tsRevokeOthers().then(ok=>{if(ok)say('sess_msg','\u2713 beendet',true);loadsess()})}
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
    return _page(auth, t("logout"), body)


def _gate_logout(auth, ctx) -> str:
    """ctx: scope ("" = ask, otherwise "app"/"all" for confirmation), app_name, next. Lives on the
    app's host under /.tinysesam/ — the forms therefore target `logout` relatively."""
    t = auth.t
    name = ctx.get("app_name") or t("gate.this_app")

    def knopf(scope, text):
        return (f"<form method=post action='logout'>{_cf(ctx)}"
                f"<input type=hidden name=scope value='{_e(scope)}'>"
                f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>"
                f"<button type=submit>{_e(text)}</button></form>")

    if ctx.get("scope") in ("app", "all"):
        frage = t("gate.confirm_app", name=name) if ctx["scope"] == "app" else t("gate.confirm_all")
        knoepfe = knopf(ctx["scope"], t("logout"))
    else:
        frage = t("gate.ask", name=name)
        knoepfe = knopf("app", t("gate.only_app", name=name)) + knopf("all", t("gate.everywhere"))
    body = (f"<h1>{_e(t('logout'))}</h1><div class=hint>{_e(frage)}</div>{knoepfe}"
            f"<div class=hint><a href='/'>{_e(t('cancel'))}</a></div>")
    return _page(auth, t("logout"), body)


def _gate_logged_out(auth, ctx) -> str:
    """ctx: app_name, again_url (optional, default "/" of the host), redirect_sec (optional). After signing out — with
    a way back that starts a NEW sign-in. With `redirect_sec` > 0 ("direct" mode, PO 2026-10-10) it goes
    there by itself after that many seconds: a meta refresh, no script; the bar runs down in CSS only."""
    t = auth.t
    ziel = ctx.get("again_url") or "/"
    try:
        sek = max(0, min(300, int(ctx.get("redirect_sec") or 0)))
    except (TypeError, ValueError):
        sek = 0
    kopf, weiter = "", ""
    if sek:
        kopf = (f"<meta http-equiv=refresh content='{sek};url={_e(ziel)}'>"
                f"<style>@keyframes tsweiter{{from{{transform:scaleX(1)}}to{{transform:scaleX(0)}}}}"
                f".tsweiter i{{animation:tsweiter {sek}s linear forwards}}</style>")
        weiter = (f"<div class=hint role=status>{_e(t('gate.login_soon', n=sek))}</div>"
                  f"<div class=tsweiter aria-hidden=true><i></i></div>")
    body = (f"<h1>{_e(t('gate.logged_out_title'))}</h1><div class=hint>{_e(t('gate.logged_out'))}</div>{weiter}"
            f"<a class=btn2 href='{_e(ziel)}'>{_e(t('gate.login_now') if sek else t('gate.login_again'))}</a>")
    return _page(auth, t("gate.logged_out_title"), body, kopf=kopf)


def _gateway_home(auth, ctx) -> str:
    """ctx: user_name. Gateway start page for signed-in users — whoever opens `/` sees who they are
    signed in as, and can sign out. (Until 0.24.1 `/` answered with a JSON 404.)"""
    t = auth.t
    body = (f"<h1>{_e(t('gw.title'))}</h1>"
            f"<div class=hint>{_e(t('gw.signed_in_as', name=ctx.get('user_name', '')))}</div>"
            f"<div class=hint>{_e(t('gw.hint'))}</div>"
            f"<form method=post action='__TS_P__/auth/logout'>{_cf(ctx)}"
            f"<button type=submit>{_e(t('logout'))}</button></form>")
    return _page(auth, t("gw.title"), body)


def _magic_invalid(auth, ctx) -> str:
    t = auth.t
    body = (f"<h1>{_e(t('magic.invalid_title'))}</h1>"
            f"<a class=btn2 href='__TS_P__/auth/login'>{_e(t('magic.to_login'))}</a>")
    return _page(auth, t("magic.invalid_title"), body, unten=_meldungen([("fehler", t("magic.invalid"))]))


def _resource_unlock(auth, ctx) -> str:
    """ctx: name, kind ('pin'|'password'), label, next, error. Shared resource secret."""
    t = auth.t
    meldungen = _meldungen([("fehler", ctx.get("error"))])
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
    return _page(auth, str(ctx.get("label") or lbl), body, unten=meldungen)


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
    meldungen = _meldungen([("fehler", ctx.get("error"))])
    methods = ctx.get("methods")
    methods = ["password"] if methods is None else list(methods)
    kopf = (f"<h1>{_e(t('reauth.title'))}</h1>"
            f"<div class=hint>{_e(t('reauth.hint', user=ctx.get('username')))}</div>")
    fuss = f"<div class=hint><a href='__TS_P__/auth/logout'>{_e(t('logout'))}</a></div>"
    if not methods:
        return _page(auth, t("reauth.title"), kopf + fuss, unten=meldungen)
    fields = f"<div class=or>{_e(t('or'))}</div>".join(
        _stepup_field(auth, m, i == 0) for i, m in enumerate(methods))
    body = (kopf
            + f"<form method=post action='__TS_P__/auth/reauth'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"{fields}<button type=submit>{_e(t('reauth.submit'))}</button></form>"
            + fuss)
    return _page(auth, t("reauth.title"), body, unten=meldungen)


def _pin(auth, ctx) -> str:
    """ctx: next, error, username (optional). PIN entry — without a user field if already signed in."""
    t = auth.t
    meldungen = _meldungen([("fehler", ctx.get("error"))])
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
    return _page(auth, t("pin.title"), body, top=_demobar(auth, pin=True, ctx=ctx), unten=meldungen)


def _totp_setup(auth, ctx) -> str:
    """ctx: data = {secret, uri, qr} — or `None`/missing for the first step.

    Two states, one page: without `data` there is only a POST form that explicitly
    starts the setup. The secret is created only with this click (B2-1) — a GET that creates
    one can be triggered from a foreign page and invalidates an attempt in progress.
    """
    t = auth.t
    data = ctx.get("data")
    if not data:
        body = (f"<h1>{_e(t('setup.title'))}</h1>"
                f"<div class=hint>{_e(t('setup.start_hint'))}</div>"
                f"<form method=post action='__TS_P__/auth/totp/setup/start'>{_cf(ctx)}"
                f"<input type=hidden name=next value='{_e(ctx.get('next') or '/')}'>"
                f"<button type=submit>{_e(t('setup.start'))}</button></form>")
        return _page(auth, t("setup.title"), body)
    qr = f"<img class=qr src='{data['qr']}'>" if data.get("qr") else ""
    ok_msg = _e(t("setup.ok")).replace("'", "\\'")
    bad_msg = _e(t("err.code")).replace("'", "\\'")
    body = (f"<h1>{_e(t('setup.title'))}</h1>"
            f"<div class=hint>{_e(t('setup.scan'))}</div>"
            f"{qr}"
            f"<div class=hint>{_e(t('setup.manual'))}</div><div class=mono>{_e(data['secret'])}</div>"
            f"<form id=tstotp data-next='{_e(ctx.get('next') or '/')}'>"
            f"<label>{_e(t('setup.code'))}</label>"
            f"<input name=code class=code inputmode=numeric maxlength=6 autofocus>"
            f"<button type=submit>{_e(t('setup.activate'))}</button></form>"
            f"<div class=hint id=msg></div>"
            "<script>function tsCsrf(){return (document.cookie.match(/(?:^|; )" + _e(auth.csrf_cookie_name) + "=([^;]+)/)||[])[1]||''}"
            "async function conf(e){e.preventDefault();const c=e.target.code.value;"
            "const r=await fetch('__TS_P__/auth/totp/setup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token':tsCsrf()},"
            "body:'code='+encodeURIComponent(c)+'&next='+encodeURIComponent(e.target.dataset.next||'/')});"
            "const j=await r.clone().json();"
            f"document.getElementById('msg').textContent=j.ok?'{ok_msg}':'{bad_msg}';"
            # B1-7 on this page too (A-5): it is the path on which TOTP comes into being.
            "await offer(r);"
            # Under the mandatory chain the sign-in is complete with the confirmation (A-1) —
            # on to the target instead of a page that invites typing the code again.
            "if(j.ok&&j.next){location.href=j.next}return false}"
            "document.getElementById('tstotp').addEventListener('submit',conf)</script>"
            + _revoke_js(auth, "'__TS_P__/auth/account?revoke_others=1'"
                         if getattr(auth.cfg, "account_enabled", False) else ""))
    return _page(auth, t("setup.title"), body)


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
    if (r.ok) location.href = (await r.json()).redirect || '__TS_P__/'; else alert('Passkey-Login fehlgeschlagen');
  } catch(e){ alert('Passkey abgebrochen: '+e); }
});
</script>
"""


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
    "register": _register,
    "magic_request": _magic_request,
    "magic_invalid": _magic_invalid,
    "magic_confirm": _magic_confirm,
    "error": _error,
    "forgot": _forgot,
    "reset": _reset,
    "totp_setup": _totp_setup,
}

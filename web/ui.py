"""Der Rumpf jeder Seite — Kopf, zwei Navigationsreihen, Fußzeile. Eine Quelle für alles.

Benutzt von:
  * `web/site.py`      — die statische Projekt-Website (GitHub Pages)
  * `examples/showcase.py` — das Demo-Frontend
  * und über `brand_header`/`brand_footer` auch von den **eingebauten** TinySesam-Seiten
    (Login, PIN, Konto, Admin-Panel, Fehlerseiten). Dieselbe Nav, dieselbe Fußzeile, überall.

Aufbau des Kopfes (ein Container, drei Zeilen):

    <header class=shell>
      Titelzeile   — Marke; auf der Startseite ersetzt der große Titelbereich sie
      Navreihe 1   — links die Seiten (+ Aufklapper), rechts Konto bzw. An-/Abmelden
      Navreihe 2   — links Verweise als Icon, rechts Sprache und Hell/Dunkel
    </header>

Kein FastAPI-Import: der Website-Generator kommt ohne laufende App aus.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from html import escape

LANGS = ("en", "de")


# ---------------------------------------------------------------------- Icons
_PATHS = {
    "github": 'M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.4 7.4 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z',
    "book": 'M0 1.75A.75.75 0 0 1 .75 1h4.253c1.227 0 2.317.59 3 1.501A3.743 3.743 0 0 1 11.006 1h4.245a.75.75 0 0 1 .75.75v10.5a.75.75 0 0 1-.75.75h-4.507a2.25 2.25 0 0 0-1.591.659l-.622.621a.75.75 0 0 1-1.06 0l-.622-.621A2.25 2.25 0 0 0 5.258 13H.75a.75.75 0 0 1-.75-.75Zm7.251 10.324.004-5.073-.002-2.253A2.25 2.25 0 0 0 5.003 2.5H1.5v9h3.757a3.75 3.75 0 0 1 1.994.574ZM8.755 4.75l-.004 7.322a3.752 3.752 0 0 1 1.992-.572H14.5v-9h-3.495a2.25 2.25 0 0 0-2.25 2.25Z',
    "sun": 'M8 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6Zm0-9.5a.75.75 0 0 1 .75.75v1a.75.75 0 0 1-1.5 0v-1A.75.75 0 0 1 8 1.5Zm0 11a.75.75 0 0 1 .75.75v1a.75.75 0 0 1-1.5 0v-1A.75.75 0 0 1 8 12.5ZM14.5 8a.75.75 0 0 1-.75.75h-1a.75.75 0 0 1 0-1.5h1A.75.75 0 0 1 14.5 8Zm-11 0a.75.75 0 0 1-.75.75h-1a.75.75 0 0 1 0-1.5h1A.75.75 0 0 1 3.5 8Zm9.1-4.6a.75.75 0 0 1 0 1.06l-.7.71a.75.75 0 1 1-1.07-1.06l.71-.71a.75.75 0 0 1 1.06 0ZM4.87 11.13a.75.75 0 0 1 0 1.06l-.71.71A.75.75 0 0 1 3.1 11.84l.71-.71a.75.75 0 0 1 1.06 0Zm7.73.71a.75.75 0 1 1-1.06 1.06l-.71-.71a.75.75 0 0 1 1.06-1.06ZM4.87 4.87A.75.75 0 0 1 3.81 4.16l-.71-.7A.75.75 0 0 1 4.16 2.39l.71.71a.75.75 0 0 1 0 1.06Z',
    "moon": 'M9.6 1.2a6.8 6.8 0 1 0 5.2 8.1A5.5 5.5 0 0 1 9.6 1.2Z',
    "person": 'M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm0 1.5c-2.6 0-4.8 1.5-5.5 3.6-.2.6.3 1.2.9 1.2h9.2c.6 0 1.1-.6.9-1.2C12.8 11 10.6 9.5 8 9.5Z',
}


def icon(name: str) -> str:
    return f'<svg viewBox="0 0 16 16" aria-hidden="true"><path d="{_PATHS[name]}"/></svg>'


# ---------------------------------------------------------------------- Bausteine
def link(href: str, label: str, active: bool = False) -> str:
    return f"<a class='{'on' if active else ''}' href='{href}'>{label}</a>"


def icon_link(href: str, name: str, title: str) -> str:
    return f'<a class=ilink href="{href}" title="{title}" aria-label="{title}">{icon(name)}</a>'


def dropdown(summary: str, items_html: str, right: bool = False, active: bool = False) -> str:
    """Aufklapper. `active` markiert nur den Auslöser — von selbst aufspringen soll er nicht."""
    cls = "dd r" if right else "dd"
    return (f"<details class='{cls}'><summary class='{'on' if active else ''}'>{summary}</summary>"
            f"<div class=ddmenu>{items_html}</div></details>")


def menu(summary: str, entries) -> str:
    """Aufklapper mit einfachen Links: `entries` = (href, label)."""
    return dropdown(summary, "".join(f"<a href='{h}'>{l}</a>" for h, l in entries), right=True)


def _seg(label: str, *, href: str = None, on: bool = False, data: str = "") -> str:
    cls = f"seg{' on' if on else ''}"
    if href:
        return f"<a class='{cls}' href='{href}'>{label}</a>"
    return f"<button class='{cls}' type=button {data}>{label}</button>"


def lang_pill(hrefs: dict, lang: str) -> str:
    """Sprache als Zweisegment-Pille. `hrefs` bildet Sprachcode → Ziel-URL ab."""
    segs = "".join(_seg(c.upper(), href=hrefs[c], on=c == lang) for c in LANGS)
    return f"<span class=pill2>{segs}</span>"


def theme_pill(light: str = "Hell", dark: str = "Dunkel") -> str:
    """Hell/Dunkel. Das aktive Segment markiert `UI_JS` beim Laden (kennt die Systemeinstellung)."""
    segs = (_seg(icon("sun"), data=f'data-theme=light title="{light}"')
            + _seg(icon("moon"), data=f'data-theme=dark title="{dark}"'))
    return f"<span class=pill2 id=ts-theme>{segs}</span>"


# ---------------------------------------------------------------------- Rumpf
@dataclass(frozen=True)
class Labels:
    """Alles, was der Rumpf an Text braucht — einmal je Sprache."""
    account: str
    admin: str
    logout: str
    login: str
    register: str
    docs: str
    theme_light: str
    theme_dark: str
    changelog: str
    security: str
    license: str
    legal: str
    credits: str


@dataclass(frozen=True)
class Nav:
    """Wie der Rumpf einer App aussieht — einmal deklarieren, überall benutzen."""
    brand_href: str
    icon_url: str
    repo: str
    css_href: str = "theme.css"   # Farbpalette; die Demo liefert sie unter einem absoluten Pfad
    flows_href: str = "flows.html"   # Ziel des „alle Login-Wege"-Verweises
    legal_href: str = "legal.html"   # Impressum + Datenschutz
    pages: tuple = ()          # ((href, label), …) — links in der ersten Navreihe
    examples: tuple = ()       # ((href, label, beschreibung), …) — als Aufklapper daneben
    examples_label: str = ""
    auth: bool = False         # rechts Konto/Abmelden bzw. An-/Registrieren anbieten


@dataclass
class Ctx:
    """Der Zustand dieses einen Requests."""
    lang: str
    labels: Labels
    lang_hrefs: dict          # Sprachcode → URL derselben Seite
    path: str = "/"
    user: dict | None = None
    is_admin: bool = False
    brand: bool = True        # False = der große Titelbereich ersetzt die Marke
    hero: str = ""            # Titelbereich (nur Startseite)
    extra_head: str = field(default="")


def _row_auth(ctx: Ctx) -> str:
    lb = ctx.labels
    if not ctx.user:
        return (f"<a class='btn ghost' href='/auth/register'>{lb.register}</a>"
                f"<a class='btn primary' href='/auth/login'>{lb.login}</a>")
    entries = [("/auth/account", lb.account)]
    if ctx.is_admin:
        entries.append(("/auth/admin", lb.admin))
    entries.append(("/auth/logout", lb.logout))
    return menu(icon("person") + escape(str(ctx.user["username"])), entries)


def header(ctx: Ctx, nav: Nav) -> str:
    """Titelzeile + zwei Navreihen in einem Container. Auf jeder Seite identisch."""
    lb = ctx.labels
    if ctx.hero:
        title = ctx.hero
    elif ctx.brand:
        title = (f"<a class=brand href='{nav.brand_href}'><img src='{nav.icon_url}' alt=''>"
                 f"<span><b>Tiny</b>Sesam</span></a>")
    else:
        title = ""

    left = "".join(link(h, l, ctx.path == h) for h, l in nav.pages)
    if nav.examples:
        items = "".join(f"<a href='{h}'><b>{l}</b><span>{d}</span></a>" for h, l, d in nav.examples)
        left += dropdown(nav.examples_label, items,
                         active=any(ctx.path == h for h, _, _ in nav.examples))
    right1 = _row_auth(ctx) if nav.auth else ""

    left2 = icon_link(nav.repo, "github", "GitHub") + icon_link(f"{nav.repo}#readme", "book", lb.docs)
    right2 = lang_pill(ctx.lang_hrefs, ctx.lang) + theme_pill(lb.theme_light, lb.theme_dark)

    return (f"<header class=shell>{title}"
            f"<nav class='row pages'><span class=l>{left}</span><span class=r>{right1}</span></nav>"
            f"<nav class='row tools'><span class=l>{left2}</span><span class=r>{right2}</span></nav>"
            f"</header>")


def footer(ctx: Ctx, nav: Nav) -> str:
    """Fußzeile — auf jeder Seite dieselbe."""
    lb = ctx.labels
    return (f'<footer><div class=inner><a href="{nav.repo}">GitHub</a>·'
            f'<a href="{nav.repo}/blob/main/CHANGELOG.md">{lb.changelog}</a>·'
            f'<a href="{nav.repo}/blob/main/SECURITY.md">{lb.security}</a>·'
            f'<a href="{nav.repo}/blob/main/LICENSE">{lb.license}</a>·'
            f'<a href="{nav.legal_href}">{lb.legal}</a>'
            f'<div class=credits>{lb.credits}</div></div></footer>')


def shell(ctx: Ctx, nav: Nav, body: str) -> str:
    """Kopf + Inhalt + Fußzeile — der Teil, den jede Seite gemeinsam hat."""
    return f"{header(ctx, nav)}\n<main>{body}</main>\n{footer(ctx, nav)}"


def _head(nav: Nav, lang: str, title: str, desc: str, css: str, extra: str = "") -> str:
    return (f'<!doctype html>\n<html lang="{lang}" data-lang="{lang}">\n<head>\n<meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            f'<title>{escape(title)}</title>\n'
            + (f'<meta name="description" content="{escape(desc)}">\n' if desc else "")
            + f'<link rel="icon" href="{nav.icon_url}">\n'
              f'<link rel="stylesheet" href="{nav.css_href}">\n'
              f'<style>{UI_CSS}{css}</style>{UI_JS}{extra}\n</head>\n')


def document(ctx: Ctx, nav: Nav, *, title: str, desc: str = "", css: str = "", body: str = "") -> str:
    """Serverseitig gerenderte Seite — die App kennt die Sprache schon."""
    return (_head(nav, ctx.lang, title, desc, css, ctx.extra_head)
            + f"<body>\n{shell(ctx, nav, body)}\n</body>\n</html>\n")


def static_document(nav: Nav, css: str, variants: dict) -> str:
    """Eine Datei, beide Sprachen — für GitHub Pages, das kein `?lang=` auswerten kann.

    `variants` = {lang: (title, desc, shell_html)} — `shell_html` kommt aus `shell(ctx, nav, body)`.
    `LANG_JS` wählt beim Laden: `?lang=` schlägt Cookie schlägt Browsersprache. **Derselbe Parameter,
    dasselbe Cookie wie in der App** — es gibt genau ein Sprachsystem, keine Sprach-Dateinamen.
    """
    first = LANGS[0]
    title, desc, _ = variants[first]
    titles = {lang: v[0] for lang, v in variants.items()}
    body = "".join(f'<div class="l-{lang}">{v[2]}</div>' for lang, v in variants.items())
    script = f"<script>window.TS_TITLES={json.dumps(titles)};</script>{LANG_JS}"
    return (_head(nav, first, title, desc, css + LANG_CSS)
            + f"<body>\n{body}\n{script}\n</body>\n</html>\n")


LANG_COOKIE = "ts_lang"

# Nur für die statischen Seiten: sie tragen beide Sprachen und blenden eine aus.
LANG_CSS = "".join(f'html[data-lang="{l}"] .l-{o}{{display:none}}'
                   for l in LANGS for o in LANGS if l != o)

LANG_JS = """<script>
(function(){
  var LANGS = %s;
  function cookie(n){var m=document.cookie.match(new RegExp('(?:^|; )'+n+'=([^;]*)')); return m?m[1]:null;}
  var q = new URLSearchParams(location.search).get('lang');
  var l = q || cookie('%s') || (navigator.language||'en').slice(0,2);
  if(LANGS.indexOf(l) < 0) l = LANGS[0];
  document.cookie = '%s=' + l + ';path=/;max-age=31536000;samesite=lax';
  var r = document.documentElement;
  r.lang = l; r.setAttribute('data-lang', l);
  if(window.TS_TITLES && TS_TITLES[l]) document.title = TS_TITLES[l];
})();
</script>""" % (json.dumps(list(LANGS)), LANG_COOKIE, LANG_COOKIE)


# ---------------------------------------------------------------------- Aussehen
# `--nav-w` setzt jede Seite auf ihre Inhaltsbreite; `--nav-fs` ist die EINE Schriftgröße
# der Leisten — Abstufung wäre dort nur Unruhe.
UI_CSS = """
:root{--nav-w:900px;--nav-fs:14px}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--ts-font);
  line-height:1.65;font-size:17px;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
a:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:4px}
code{font-family:var(--ts-mono);font-size:.86em;background:var(--chip);border:1px solid var(--line);
  border-radius:5px;padding:1px 5px;color:var(--ink)}
main{max-width:var(--nav-w);margin:0 auto;padding:56px 22px 72px}

/* ---- Kopf: Titelzeile + zwei Navreihen ---- */
header.shell>*{max-width:var(--nav-w);margin:0 auto;font-size:var(--nav-fs)}
header.shell .brand{display:flex;align-items:center;gap:10px;padding:14px 22px;
  text-decoration:none;color:var(--ink);width:fit-content}
header.shell .brand img{width:38px;height:38px}
header.shell .brand span{font-weight:700;font-size:22px}
header.shell .brand b{color:var(--accent)}
header.shell .brand:hover{text-decoration:none}
nav.row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
nav.row .l,nav.row .r{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
/* eigener Stapelkontext: sonst malen animierte Abschnitte über ein offenes Dropdown */
nav.pages{position:relative;z-index:30;background:var(--paper);padding:11px 22px;
  border-bottom:1px solid var(--line)}
nav.tools{position:relative;z-index:29;padding:8px 22px}
/* :not(.ilink) — sonst schlaegt diese Regel (0,1,2) das .ilink-Padding (0,1,0) und quetscht das Icon */
nav.row a:not(.ilink){padding:6px 11px}
nav.row a{display:inline-flex;align-items:center;gap:6px;border-radius:8px;
  color:var(--muted);white-space:nowrap;text-decoration:none;font-size:var(--nav-fs)}
nav.row a:hover{background:var(--chip);color:var(--ink);text-decoration:none}
nav.row a.on{background:var(--chip);color:var(--ink)}
nav.row code{font-size:1em;background:none;border:0;padding:0;color:inherit}
.btn{display:inline-flex;align-items:center;gap:8px;padding:9px 17px;border-radius:10px;
  font-weight:500;font-size:15px}
.btn svg{width:16px;height:16px;fill:currentColor;flex:0 0 auto}
.btn.primary{background:var(--accent);color:#fff}
.btn.primary:hover{text-decoration:none;filter:brightness(1.05)}
.btn.ghost{border:1px solid var(--line);color:var(--ink)}
.btn.ghost:hover{text-decoration:none;border-color:var(--accent)}
nav .btn{padding:6px 13px;font-size:var(--nav-fs);border-radius:9px}
/* genauso hoch wie die Wechsel-Pillen (18px Segment + 2px Polsterung + 2px Rand = 22px) */
.ilink{display:inline-flex;align-items:center;justify-content:center;width:26px;height:22px;
  padding:0;border-radius:7px;color:var(--muted)}
.ilink:hover{background:var(--chip);color:var(--ink);text-decoration:none}
.ilink svg{width:20px;height:20px;flex:0 0 auto;fill:currentColor}

/* ---- Zweisegment-Pille (Sprache, Hell/Dunkel) ---- */
.pill2{display:inline-flex;align-items:center;gap:1px;padding:1px;border-radius:999px;
  background:var(--chip);border:1px solid var(--line)}
.pill2 .seg{display:inline-flex;align-items:center;justify-content:center;min-width:24px;height:18px;
  padding:0 6px;border:0;border-radius:999px;background:none;color:var(--muted);cursor:pointer;
  font:inherit;font-size:10px;font-weight:700;letter-spacing:.04em;text-decoration:none;line-height:1}
.pill2 .seg:hover{color:var(--ink);text-decoration:none}
.pill2 .seg.on{background:var(--card);color:var(--ink);box-shadow:0 1px 3px rgba(90,60,70,.12)}
.pill2 .seg svg{width:14px;height:14px;fill:currentColor}

/* ---- Aufklapper ---- */
.dd{position:relative}
.dd summary{list-style:none;cursor:pointer;padding:6px 11px;border-radius:8px;color:var(--muted);
  display:inline-flex;align-items:center;gap:7px;white-space:nowrap;font-size:var(--nav-fs)}
.dd summary::-webkit-details-marker{display:none}
.dd summary::after{content:"▾";font-size:11px}
.dd summary:hover,.dd[open] summary,.dd summary.on{background:var(--chip);color:var(--ink)}
.dd summary svg{width:16px;height:16px;fill:currentColor}
.ddmenu{position:absolute;z-index:40;top:calc(100% + 6px);min-width:200px;padding:6px;
  background:var(--card);border:1px solid var(--line);border-radius:12px;
  box-shadow:0 14px 40px rgba(90,60,70,.14)}
.dd.r .ddmenu{right:0}
.dd:not(.r) .ddmenu{left:0}
/* muss `nav.row a` schlagen (gleiche Spezifität) — sonst stehen die Einträge nebeneinander */
.ddmenu a,nav.row .ddmenu a{display:block;padding:8px 10px;border-radius:8px;color:var(--ink);
  white-space:normal;font-size:var(--nav-fs)}
.ddmenu a:hover,nav.row .ddmenu a:hover{background:var(--chip);text-decoration:none}
.ddmenu b{display:block;font-weight:600}
.ddmenu span{display:block;color:var(--muted);font-size:12.5px}

/* ---- Fußzeile ---- */
footer{margin-top:72px;color:var(--muted);font-size:14px}
footer .inner{max-width:var(--nav-w);margin:0 auto;padding:26px 22px 60px;text-align:center;
  border-top:1px solid var(--line)}
footer a{margin:0 9px}
footer .credits{margin-top:14px;font-size:12.5px}

@media (prefers-reduced-motion:no-preference){
  header.shell>*{animation:rise .5s ease both}
  @keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
}
"""

UI_JS = """<script>
// Hell/Dunkel früh anwenden, damit beim Laden nichts umspringt. theme.css kennt [data-theme].
(function(){var t=localStorage.getItem('ts-theme'); if(t) document.documentElement.dataset.theme=t;})();
document.addEventListener('DOMContentLoaded',function(){
  var root=document.documentElement;
  var cur=function(){return root.dataset.theme
    || (matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light');};
  var paint=function(){document.querySelectorAll('#ts-theme .seg').forEach(function(b){
    b.classList.toggle('on', b.dataset.theme===cur());});};
  document.querySelectorAll('#ts-theme .seg').forEach(function(b){
    b.addEventListener('click',function(){
      root.dataset.theme=b.dataset.theme; localStorage.setItem('ts-theme',b.dataset.theme); paint();});
  });
  paint();
});
// <details> schliesst von sich aus nicht bei Klick daneben.
document.addEventListener('click',function(e){
  document.querySelectorAll('details.dd[open]').forEach(function(d){
    if(!d.contains(e.target)) d.open=false;});
});
document.addEventListener('keydown',function(e){
  if(e.key==='Escape') document.querySelectorAll('details.dd[open]').forEach(function(d){d.open=false;});
});
</script>"""

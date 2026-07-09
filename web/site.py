"""Die Projekt-Website — eine Quelle, zwei Sprachen, zwei Seiten.

    index.html / index.de.html   → Überblick
    flows.html / flows.de.html   → alle Login-Wege als Diagramm (Inhalt: web/flows.py)

`web/build.py` schreibt die vier Dateien für GitHub Pages (die Action baut sie bei jedem Push).
Die Demo rendert dieselben Funktionen zur Laufzeit — sie braucht also keine gebauten Dateien.

Kein FastAPI-Import: Generator und Demo teilen sich diesen Code.
"""
from .flows import CSS as FLOW_CSS, render as render_flow_list

REPO = "https://github.com/Ollornog/TinySesam"
LANGS = ("en", "de")


def page_url(page: str, lang: str) -> str:
    """`index`/`flows` + Sprache → Dateiname. Englisch bleibt ohne Suffix (Standard-Einstieg)."""
    return f"{page}.html" if lang == "en" else f"{page}.de.html"



# ---------------------------------------------------------------- Navigation (eine Quelle)
# Beide Leisten werden hier gebaut — die Website nutzt sie, das Showcase auch. Nur der *Inhalt*
# unterscheidet sich (die Demo kennt Login-Status und Beispielseiten, die Website nicht).
NAV_CSS = """
  nav.top{display:flex;align-items:center;justify-content:space-between;gap:14px;
    max-width:900px;margin:0 auto;padding:14px 22px}
  nav.top.nobrand{justify-content:flex-end;padding-bottom:0}
  nav.top .brand{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--ink)}
  nav.top .brand img{width:30px;height:30px}
  nav.top .brand span{font-weight:700;font-size:18px}
  nav.top .brand b{color:var(--accent)}
  nav.top .right{display:flex;align-items:center;gap:10px;font-size:14px}
  nav.sub{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
    max-width:900px;margin:0 auto;padding:9px 22px;font-size:14px;
    border-bottom:1px solid var(--line)}
  nav.sub .left,nav.sub .right{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
  nav.sub a{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:8px;
    color:var(--muted);white-space:nowrap;text-decoration:none}
  nav.sub a:hover{background:var(--chip);color:var(--ink);text-decoration:none}
  nav.sub a.on{background:var(--chip);color:var(--ink)}
  nav.sub code{font-size:.86em;background:none;border:0;padding:0;color:inherit;font-family:var(--ts-mono)}
  nav .btn{padding:6px 13px;font-size:14px;border-radius:9px}
  nav .btn.ghost{color:var(--ink)}
  .dd{position:relative}
  .dd summary{list-style:none;cursor:pointer;padding:5px 11px;border-radius:8px;color:var(--muted);
    display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
  .dd summary::-webkit-details-marker{display:none}
  .dd summary::after{content:"▾";font-size:11px}
  .dd summary:hover,.dd[open] summary{background:var(--chip);color:var(--ink)}
  .ddmenu{position:absolute;z-index:20;top:calc(100% + 6px);min-width:210px;padding:6px;
    background:var(--card);border:1px solid var(--line);border-radius:12px;
    box-shadow:0 14px 40px rgba(90,60,70,.14)}
  .dd.r .ddmenu{right:0}
  .dd:not(.r) .ddmenu{left:0}
  /* stärker als `nav.sub a` (gleiche Spezifität, aber dort inline-flex) → Einträge untereinander */
  .ddmenu a,nav.sub .ddmenu a{display:block;padding:8px 10px;border-radius:8px;color:var(--ink);
    white-space:normal}
  .ddmenu a:hover,nav.sub .ddmenu a:hover{background:var(--chip);text-decoration:none}
  .dd summary svg{width:15px;height:15px;fill:currentColor}
  .ddmenu b{display:block;font-weight:600;font-size:14px}
  .ddmenu span{display:block;color:var(--muted);font-size:12.5px}
"""


def link(href, label, active=False) -> str:
    return f"<a class='{'on' if active else ''}' href='{href}'>{label}</a>"


def dropdown(summary, items_html, right=False, open_=False) -> str:
    cls = "dd r" if right else "dd"
    return (f"<details class='{cls}'{' open' if open_ else ''}><summary>{summary}</summary>"
            f"<div class=ddmenu>{items_html}</div></details>")


LANG_LABELS = {"en": "English", "de": "Deutsch"}


def lang_dropdown(page: str, lang: str) -> str:
    """Sprachwechsel für die Website: bleibt auf derselben Seite, wechselt die Datei."""
    items = "".join(f"<a href='{page_url(page, code)}'>{label}</a>" for code, label in LANG_LABELS.items())
    return dropdown(GLOBE_ICON + LANG_LABELS[lang], items, right=True)


def lang_dropdown_path(path: str, lang: str) -> str:
    """Sprachwechsel für Seiten ohne Sprach-Dateinamen (die Demo): hängt `?lang=` an den Pfad."""
    items = "".join(f"<a href='{path}?lang={code}'>{label}</a>" for code, label in LANG_LABELS.items())
    return dropdown(GLOBE_ICON + LANG_LABELS[lang], items, right=True)


def nav_top(right_html="", brand_href="index.html", icon="wizard.png") -> str:
    """Erste Leiste. `brand_href=None` lässt die Marke weg — für die Startseite, deren Titelbereich
    sie ohnehin groß zeigt. Die Knöpfe rechts bleiben, damit die Leiste überall dieselbe Rolle hat."""
    if brand_href is None:
        return f"<nav class='top nobrand'><span class=right>{right_html}</span></nav>"
    return (f"<nav class=top><a class=brand href='{brand_href}'><img src='{icon}' alt=''>"
            f"<span><b>Tiny</b>Sesam</span></a><span class=right>{right_html}</span></nav>")


def nav_sub(left_html, right_html="") -> str:
    return f"<nav class=sub><span class=left>{left_html}</span><span class=right>{right_html}</span></nav>"


_BASE_CSS = """
  *{box-sizing:border-box}
  html{-webkit-text-size-adjust:100%}
  body{margin:0; background:var(--paper); color:var(--ink); font-family:var(--ts-font);
    line-height:1.6; font-size:17px; -webkit-font-smoothing:antialiased}
  .wrap{max-width:720px; margin:0 auto; padding:0 22px}
  a{color:var(--accent); text-decoration:none}
  a:hover{text-decoration:underline}
  a:focus-visible{outline:2px solid var(--accent); outline-offset:3px; border-radius:4px}
  .rule{height:1px; background:var(--line); border:0; margin:44px 0}
  section{margin:38px 0}
  h2{font-size:13px; text-transform:uppercase; letter-spacing:.09em; color:var(--muted);
    font-weight:600; margin:0 0 16px}
  .btn{display:inline-flex; align-items:center; gap:8px; padding:11px 20px; border-radius:10px;
    font-size:15px; font-weight:500}
  .btn svg{width:16px; height:16px; fill:currentColor; flex:0 0 auto}
  .btn.primary{background:var(--accent); color:#fff}
  .btn.primary:hover{text-decoration:none; filter:brightness(1.05)}
  .btn.ghost{border:1px solid var(--line); color:var(--ink)}
  .btn.ghost:hover{text-decoration:none; border-color:var(--accent)}
  code{font-family:var(--ts-mono); font-size:.86em; background:var(--chip);
    border:1px solid var(--line); border-radius:5px; padding:1px 5px; color:var(--ink)}
  .note{color:var(--muted); font-size:13.5px}
  footer{border-top:1px solid var(--line); margin-top:52px; padding:26px 0 60px; text-align:center;
    color:var(--muted); font-size:14px}
  footer a{margin:0 9px}
  .lang{display:flex; justify-content:center; gap:10px; padding:14px 0 0; font-size:13.5px;
    color:var(--muted)}
  .lang b{color:var(--ink)}
"""

_INDEX_CSS = """
  header.hero{text-align:center; padding:56px 0 8px; position:relative}
  .badge{position:relative; display:inline-grid; place-items:center; width:132px; height:132px; margin-bottom:10px}
  .badge::before{content:""; position:absolute; inset:-18%; border-radius:50%;
    background:radial-gradient(circle at 50% 42%, var(--glow), transparent 68%); z-index:0}
  .badge img{position:relative; z-index:1; width:112px; height:112px; display:block}
  h1{font-family:var(--ts-serif); font-weight:600; font-size:44px; letter-spacing:-.01em;
    margin:.1em 0 .12em; text-wrap:balance}
  h1 .tiny{color:var(--accent)}
  .tagline{color:var(--muted); font-size:18px; max-width:42ch; margin:0 auto; text-wrap:balance}
  .cta{display:flex; gap:12px; justify-content:center; flex-wrap:wrap; margin:26px 0 6px}
  .chips{display:flex; flex-wrap:wrap; gap:8px}
  .chip{background:var(--chip); border:1px solid var(--line); border-radius:999px;
    padding:6px 13px; font-size:14px; color:var(--ink)}
  .chip b{color:var(--accent); font-weight:600}
  .solves{list-style:none; padding:0; margin:0; display:grid; gap:12px}
  .solves li{display:grid; grid-template-columns:auto 1fr; gap:12px; align-items:start; font-size:16px}
  .solves .yes{color:var(--accent); font-weight:700; font-family:var(--ts-serif)}
  .solves b{font-weight:600}
  .solves span{color:var(--muted)}
  .solves code{color:var(--ink)}
  .code{background:var(--code-bg); color:var(--code-fg); border-radius:12px; padding:16px 18px;
    overflow-x:auto; font-family:var(--ts-mono); font-size:13.5px; line-height:1.7}
  .code .c{color:#9b93ab} .code .k{color:var(--accent-2)} .code .s{color:#c9a98f}
  .feat{display:grid; grid-template-columns:1fr 1fr; gap:14px 26px}
  .feat div{font-size:15px}
  .feat b{display:block; font-size:15px}
  .feat span{color:var(--muted); font-size:14px}
  .feat code{font-size:.86em}
  @media (max-width:560px){ .feat{grid-template-columns:1fr} h1{font-size:36px} }
  .pos{max-width:46ch; margin:14px auto 0; padding:11px 15px; font-size:14px; color:var(--muted);
    background:var(--chip); border:1px solid var(--line); border-radius:10px; text-wrap:balance}
  .pos b{color:var(--ink); font-weight:600}
  @media (prefers-reduced-motion:no-preference){
    header.hero, nav.sub, section{animation:rise .5s ease both}
    section:nth-of-type(2){animation-delay:.05s}
    @keyframes rise{from{opacity:0; transform:translateY(8px)} to{opacity:1; transform:none}}
  }
"""

_FLOWS_CSS = """
  main{max-width:900px; margin:0 auto; padding:34px 22px 24px}
  h1{font-family:var(--ts-serif); font-weight:600; font-size:40px; letter-spacing:-.01em;
    margin:.1em 0 .12em; text-wrap:balance}
  .lead{color:var(--muted); font-size:18px; max-width:60ch; text-wrap:balance}
"""

GITHUB_ICON = ('<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 '
               '2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94'
               '-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 '
               '2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36'
               '-1.02.08-2.12 0 0 .67-.21 2.2.82a7.4 7.4 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 '
               '2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73'
               '.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/>'
               '</svg>')
GLOBE_ICON = ('<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0ZM5.78 8.75a9.6 9.6 0 0 0 1.363 4.177c.255.426.542.832.857 1.215.245-.296.551-.705.857-1.215A9.6 9.6 0 0 0 10.22 8.75Zm4.44-1.5a9.6 9.6 0 0 0-1.363-4.177c-.307-.51-.612-.919-.857-1.215a9.8 9.8 0 0 0-.857 1.215A9.6 9.6 0 0 0 5.78 7.25Zm-5.944 1.5H1.543a6.5 6.5 0 0 0 4.666 5.5c-.123-.181-.24-.365-.352-.552-.715-1.192-1.437-2.874-1.581-4.948Zm-2.733-1.5h2.733c.144-2.074.866-3.756 1.58-4.948.12-.197.237-.381.353-.552a6.5 6.5 0 0 0-4.666 5.5Zm10.181 1.5c-.144 2.074-.866 3.756-1.58 4.948-.12.197-.237.381-.353.552a6.5 6.5 0 0 0 4.666-5.5Zm2.733-1.5a6.5 6.5 0 0 0-4.666-5.5c.123.181.24.365.353.552.714 1.192 1.436 2.874 1.58 4.948Z"/></svg>')

BOOK_ICON = ('<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M0 1.75A.75.75 0 0 1 .75 1h4.253c1.227 '
             '0 2.317.59 3 1.501A3.743 3.743 0 0 1 11.006 1h4.245a.75.75 0 0 1 .75.75v10.5a.75.75 0 0 1-.75'
             '.75h-4.507a2.25 2.25 0 0 0-1.591.659l-.622.621a.75.75 0 0 1-1.06 0l-.622-.621A2.25 2.25 0 0 0 '
             '5.258 13H.75a.75.75 0 0 1-.75-.75Zm7.251 10.324.004-5.073-.002-2.253A2.25 2.25 0 0 0 5.003 '
             '2.5H1.5v9h3.757a3.75 3.75 0 0 1 1.994.574ZM8.755 4.75l-.004 7.322a3.752 3.752 0 0 1 1.992-.572'
             'H14.5v-9h-3.495a2.25 2.25 0 0 0-2.25 2.25Z"/></svg>')

T = {
    "en": {
        "title": "TinySesam — multi-method auth for FastAPI",
        "desc": "A small, reusable multi-method authentication module for FastAPI: password, PIN, "
                "passkeys, OIDC, SAML, LDAP, magic-link, TOTP — with factor chains, step-up, "
                "forward-auth and more.",
        "tagline": ("The <b>login layer for your self-built apps</b>.<br />"
                    "Super-light auth for FastAPI where you use<br /><b>only what you need</b><br />"
                    "Hang one class in front of your app and get login pages, sessions and route "
                    "guards. It grows with you."),
        "pos": ("Secures <b>your own apps</b> and <b>consumes</b> existing identity providers "
                "(OIDC, SAML, LDAP&nbsp;/&nbsp;AD). It is <b>not</b> an identity provider itself — "
                "not a Keycloak / Authentik / PocketID replacement."),
        "cta_github": "View on GitHub", "cta_docs": "Documentation",
        "meta": "MIT · Python 3.10+ · every feature optional, front end fully replaceable",
        "h_solves": "Use only what you need",
        "solves": [
            ("Just gate one page behind a PIN?", "a shared PIN or passphrase, no user account required."),
            ("Forward-auth in front of other apps, like TinyAuth?",
             "yes, via <code>/auth/forward</code> or a ready-made OIDC gateway."),
            ("Want an admin panel?", "built in. <b>Prefer it inside your own?</b> — use just the JSON API."),
            ("From “a password is enough” to “OIDC → password → TOTP”?",
             "it grows with you; every piece optional, on/off by config."),
            ("Your own look &amp; language?",
             "the whole front end is replaceable (<code>set_template</code>), texts in English or German."),
        ],
        "h_ways": "Ways to sign in",
        "chips": ["🔐 Password", "🔢 PIN", "🔑 Passkey / WebAuthn", "🌐 OIDC <b>· Entra</b>",
                  "🪪 SAML 2.0", "🗂️ LDAP / Active Directory", "✉️ Magic-link",
                  "📱 TOTP <b>+ recovery codes</b>"],
        "flows_link": "See every sign-in flow as a diagram &rarr;",
        "h_more": "And more",
        "feat": [
            ("Factor chains", "ordered combinations like OIDC → password, per route or global"),
            ("Step-up MFA", "re-confirm before sensitive routes — with a PIN, TOTP or the password"),
            ("Register &amp; invite", "self-signup, email verification, invitation links"),
            ("Sign in with what you want", "username, email or both — <code>login_identifier</code>"),
            ("Shared resource secret", "protect an area with a PIN/passphrase, no account"),
            ("Forward-auth", "guard other apps via Caddy / nginx / Traefik"),
            ("Admin panel &amp; API keys", "users, sessions, service accounts, audit log"),
            ("Hardened", "argon2, CSRF, brute-force lockout, Redis rate-limit, i18n"),
        ],
        "h_install": "Install", "h_use": "Use",
        "use_comment_router": "# /auth/* + login UI", "use_comment_guard": "# protected",
        "gateway": ('Want just SSO in front of existing apps? Run it as an '
                    f'<a href="{REPO}#as-a-pure-oidc-gateway-preset">OIDC forward-auth gateway</a>.'),
        "f_changelog": "Changelog", "f_security": "Security", "f_license": "MIT License",
        "credits": '<a href="https://www.flaticon.com/free-icons/wizard" title="wizard icons">'
                   'Wizard icons created by max.icons — Flaticon</a>',
        # Flow-Seite
        "flows_title": "TinySesam — sign-in flows",
        "flows_desc": "Every TinySesam sign-in flow as a diagram: password, PIN, TOTP, step-up, "
                      "factor chains, shared secrets, magic links, OIDC/SAML and forward-auth.",
        "flows_h1": "Sign-in flows",
        "flows_lead": ("Every way in is its own switch, and they combine. The tag next to each heading "
                       "is the config that turns it on — nothing here is mandatory, and the whole front "
                       "end is replaceable."),
        "flows_outro": ('Curious how it feels? The showcase in '
                        f'<a href="{REPO}/blob/main/examples/showcase.py"><code>examples/showcase.py</code></a> '
                        'renders these same diagrams — but marks what its own config actually has on.'),
        "nav_overview": "Overview", "nav_flows": "Sign-in flows",
    },
    "de": {
        "title": "TinySesam — Multi-Methoden-Auth für FastAPI",
        "desc": "Ein kleines, wiederverwendbares Auth-Modul für FastAPI: Passwort, PIN, Passkeys, "
                "OIDC, SAML, LDAP, Magic-Link, TOTP — mit Faktor-Ketten, Step-up, Forward-Auth "
                "und mehr.",
        "tagline": ("Der <b>Login-Mechanismus für deine selbstgebauten Apps</b>.<br />"
                    "Super-leichtes Auth für FastAPI, bei dem du<br /><b>nur nutzt, was du brauchst</b><br />"
                    "Eine Klasse davorhängen — Login-Seite, Sessions und Route-Guards inklusive. "
                    "Es wächst mit dir."),
        "pos": ("Sichert <b>deine eigenen Apps</b> und <b>nutzt</b> vorhandene IdProvider "
                "(OIDC, SAML, LDAP&nbsp;/&nbsp;AD). Es ist <b>selbst kein</b> Identity Provider — "
                "kein Ersatz für Keycloak / Authentik / PocketID."),
        "cta_github": "Auf GitHub ansehen", "cta_docs": "Dokumentation",
        "meta": "MIT · Python 3.10+ · jedes Feature optional, Frontend komplett austauschbar",
        "h_solves": "Nutze nur, was du brauchst",
        "solves": [
            ("Nur eine Seite hinter einer PIN sichern?",
             "eine geteilte PIN oder Passphrase, ganz ohne Benutzerkonto."),
            ("Forward-Auth vor fremde Apps hängen, wie TinyAuth?",
             "ja, über <code>/auth/forward</code> oder ein fertiges OIDC-Gateway."),
            ("Ein Admin-Panel?", "eingebaut. <b>Lieber in dein eigenes einbauen?</b> — dann nur die JSON-API."),
            ("Von „Passwort reicht“ bis „OIDC → Passwort → TOTP“?",
             "wächst mit — jedes Stück optional, an/aus per Config."),
            ("Eigenes Look &amp; Feel, eigene Sprache?",
             "das komplette Frontend ist austauschbar (<code>set_template</code>), Texte auf Deutsch oder Englisch."),
        ],
        "h_ways": "Wege sich anzumelden",
        "chips": ["🔐 Passwort", "🔢 PIN", "🔑 Passkey / WebAuthn", "🌐 OIDC <b>· Entra</b>",
                  "🪪 SAML 2.0", "🗂️ LDAP / Active Directory", "✉️ Magic-Link",
                  "📱 TOTP <b>+ Recovery-Codes</b>"],
        "flows_link": "Alle Login-Wege als Diagramm ansehen &rarr;",
        "h_more": "Und mehr",
        "feat": [
            ("Faktor-Ketten", "geordnete Kombinationen wie OIDC → Passwort, pro Route oder global"),
            ("Step-up-MFA", "vor sensiblen Routen erneut bestätigen — per PIN, TOTP oder Passwort"),
            ("Registrierung &amp; Einladung", "Selbst-Registrierung, E-Mail-Bestätigung, Einladungslinks"),
            ("Anmelden womit du willst", "Benutzername, E-Mail oder beides — <code>login_identifier</code>"),
            ("Geteiltes Ressourcen-Geheimnis", "einen Bereich per PIN/Passphrase schützen, ohne Konto"),
            ("Forward-Auth", "fremde Apps über Caddy / nginx / Traefik absichern"),
            ("Admin-Panel &amp; API-Keys", "Benutzer, Sitzungen, Service-Accounts, Audit-Log"),
            ("Gehärtet", "argon2, CSRF, Brute-Force-Lockout, Redis-Rate-Limit, i18n"),
        ],
        "h_install": "Installation", "h_use": "Benutzung",
        "use_comment_router": "# /auth/* + Login-UI", "use_comment_guard": "# geschützt",
        "gateway": ('Nur SSO vor bestehende Apps? Dann als '
                    f'<a href="{REPO}#as-a-pure-oidc-gateway-preset">OIDC-Forward-Auth-Gateway</a> betreiben.'),
        "f_changelog": "Changelog", "f_security": "Sicherheit", "f_license": "MIT-Lizenz",
        "credits": '<a href="https://www.flaticon.com/free-icons/wizard" title="wizard icons">'
                   'Wizard icons created by max.icons — Flaticon</a>',
        "flows_title": "TinySesam — Login-Flows",
        "flows_desc": "Jeder Login-Weg von TinySesam als Diagramm: Passwort, PIN, TOTP, Step-up, "
                      "Faktor-Ketten, geteilte Geheimnisse, Magic-Link, OIDC/SAML und Forward-Auth.",
        "flows_h1": "Login-Flows",
        "flows_lead": ("Jeder Weg hinein ist ein eigener Schalter, und sie lassen sich kombinieren. "
                       "Neben jeder Überschrift steht die Config, die ihn einschaltet — nichts davon "
                       "ist Pflicht, und das ganze Frontend ist austauschbar."),
        "flows_outro": ('Wie fühlt sich das an? Das Showcase in '
                        f'<a href="{REPO}/blob/main/examples/showcase.py"><code>examples/showcase.py</code></a> '
                        'rendert dieselben Diagramme — markiert dort aber, was seine eigene Config anhat.'),
        "nav_overview": "Überblick", "nav_flows": "Login-Flows",
    },
}


def _footer(lang: str) -> str:
    t = T[lang]
    return (f'<footer><a href="{REPO}">GitHub</a>·'
            f'<a href="{REPO}/blob/main/CHANGELOG.md">{t["f_changelog"]}</a>·'
            f'<a href="{REPO}/blob/main/SECURITY.md">{t["f_security"]}</a>·'
            f'<a href="{REPO}/blob/main/LICENSE">{t["f_license"]}</a>'
            f'<div style="margin-top:14px; font-size:12.5px">{t["credits"]}</div></footer>')


def _head(lang: str, title: str, desc: str, css: str) -> str:
    return (f'<!doctype html>\n<html lang="{lang}">\n<head>\n<meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            f'<title>{title}</title>\n<meta name="description" content="{desc}">\n'
            f'<link rel="icon" href="wizard.png">\n<link rel="stylesheet" href="theme.css">\n'
            f'<style>{_BASE_CSS}{NAV_CSS}{css}</style>\n</head>\n<body>\n')


def site_nav_top(lang: str, brand=True) -> str:
    return nav_top(f'<a href="{REPO}">GitHub</a>',
                   brand_href=page_url("index", lang) if brand else None)


def site_nav_sub(page: str, lang: str) -> str:
    """Immer dieselben Einträge — die zweite Leiste kennt weder Login-Status noch Seitenkontext."""
    t = T[lang]
    left = (link(page_url("index", lang), t["nav_overview"], page == "index")
            + link(page_url("flows", lang), t["nav_flows"], page == "flows"))
    return nav_sub(left, lang_dropdown(page, lang))


def render_index(lang: str = "en", nav1: str | None = None, nav2: str | None = None) -> str:
    """Überblick. Die erste Leiste kommt hier ohne Marke — der Titelbereich zeigt sie groß."""
    t = T[lang]
    solves = "".join(f'<li><span class="yes">✓</span><span><b>{q}</b><br />— {a}</span></li>'
                     for q, a in t["solves"])
    chips = "".join(f'<span class="chip">{c}</span>' for c in t["chips"])
    feat = "".join(f"<div><b>{h}</b><span>{d}</span></div>" for h, d in t["feat"])
    top = nav1 if nav1 is not None else site_nav_top(lang, brand=False)
    sub = nav2 if nav2 is not None else site_nav_sub("index", lang)
    return (_head(lang, t["title"], t["desc"], _INDEX_CSS) + f"""{top}<header class="hero">
    <div class="badge"><img src="wizard.png" alt="TinySesam logo" width="112" height="112"></div>
    <h1><span class="tiny">Tiny</span>Sesam</h1>
    <p class="tagline">{t["tagline"]}</p>
    <p class="pos">{t["pos"]}</p>
    <div class="cta">
      <a class="btn primary" id="cta-github" href="{REPO}">{GITHUB_ICON}{t["cta_github"]}</a>
      <a class="btn ghost" id="cta-docs" href="{REPO}#readme">{BOOK_ICON}{t["cta_docs"]}</a>
    </div>
    <p class="note">{t["meta"]}</p>
  </header>
  {sub}
  <div class="wrap">

  <section><h2>{t["h_solves"]}</h2><ul class="solves">{solves}</ul></section>

  <section><h2>{t["h_ways"]}</h2><div class="chips">{chips}</div>
    <p class="note" style="margin-top:16px"><a href="{page_url("flows", lang)}">{t["flows_link"]}</a></p>
  </section>

  <section><h2>{t["h_more"]}</h2><div class="feat">{feat}</div></section>

  <section><h2>{t["h_install"]}</h2>
    <div class="code">pip install <span class="s">"tinysesam[all] @ git+{REPO}.git"</span></div>
  </section>

  <section><h2>{t["h_use"]}</h2>
    <div class="code"><span class="k">auth</span> = TinySesam(TinySesamConfig(db_path=<span class="s">"app.db"</span>))
app.include_router(<span class="k">auth</span>.router())          <span class="c">{t["use_comment_router"]}</span>

<span class="k">@app</span>.get(<span class="s">"/"</span>)
<span class="k">def</span> home(user = Depends(<span class="k">auth</span>.require_user)):   <span class="c">{t["use_comment_guard"]}</span>
    <span class="k">return</span> {{<span class="s">"hi"</span>: user[<span class="s">"username"</span>]}}</div>
    <p class="note" style="margin-top:14px">{t["gateway"]}</p>
  </section>

  {_footer(lang)}
</div>
</body>
</html>
""")


def render_flows(lang: str = "en", nav1: str | None = None, nav2: str | None = None) -> str:
    t = T[lang]
    top = nav1 if nav1 is not None else site_nav_top(lang)
    sub = nav2 if nav2 is not None else site_nav_sub("flows", lang)
    return (_head(lang, t["flows_title"], t["flows_desc"], _FLOWS_CSS + FLOW_CSS) + f"""{top}{sub}
<main>
  <h1>{t["flows_h1"]}</h1>
  <p class="lead">{t["flows_lead"]}</p>
  <hr class="rule">
  {render_flow_list(lang, cfg=None)}
  <hr class="rule">
  <p class="lead">{t["flows_outro"]}</p>
</main>
<div class="wrap">{_footer(lang)}</div>
</body>
</html>
""")


# Dateiname → fertiges HTML. Der Generator schreibt das, die Demo liefert es zur Laufzeit aus.
def build_pages() -> dict:
    out = {}
    for lang in LANGS:
        out[page_url("index", lang)] = render_index(lang)
        out[page_url("flows", lang)] = render_flows(lang)
    return out

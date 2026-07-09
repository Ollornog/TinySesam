"""Die Projekt-Website — eine Quelle, zwei Sprachen, zwei Seiten.

    index.html / index.de.html   → Überblick
    flows.html / flows.de.html   → alle Login-Wege als Diagramm (Inhalt: web/flows.py)

`web/build.py` schreibt die vier Dateien für GitHub Pages (die Action baut sie bei jedem Push).
Die Demo rendert dieselben Funktionen zur Laufzeit — sie braucht keine gebauten Dateien.

Hier stehen nur **Texte und Seiteninhalt**. Kopf, Navigation und Fußzeile kommen aus `web/ui.py`,
damit Website, Demo und die eingebauten TinySesam-Seiten denselben Rumpf tragen.
"""
from .flows import CSS as FLOW_CSS, render as render_flow_list
from .ui import Ctx, Labels, Nav, LANGS, document, icon

REPO = "https://github.com/Ollornog/TinySesam"


def page_url(page: str, lang: str) -> str:
    """`index`/`flows` + Sprache → Dateiname. Englisch bleibt ohne Suffix (Standard-Einstieg)."""
    return f"{page}.html" if lang == "en" else f"{page}.de.html"


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
        "extras": ("<code>[all]</code> pulls every optional dependency. Take only what you need: "
                   "<code>[argon2]</code> stronger hashing · <code>[oidc]</code> OIDC login · "
                   "<code>[saml]</code> SAML&nbsp;2.0 · <code>[ldap]</code> LDAP/AD · "
                   "<code>[passkey]</code> WebAuthn · <code>[qr]</code> TOTP&nbsp;QR code · "
                   "<code>[redis]</code> rate limit across workers. Combine them: "
                   "<code>[oidc,argon2]</code>. Without any extra you still get password + TOTP "
                   "(stdlib scrypt)."),
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
        "l_account": "Account", "l_admin": "Admin panel", "l_logout": "Sign out",
        "l_login": "Sign in", "l_register": "Register", "l_light": "Light", "l_dark": "Dark",
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
        "extras": ("<code>[all]</code> zieht alle optionalen Abhängigkeiten. Nimm nur, was du brauchst: "
                   "<code>[argon2]</code> stärkeres Hashing · <code>[oidc]</code> OIDC-Login · "
                   "<code>[saml]</code> SAML&nbsp;2.0 · <code>[ldap]</code> LDAP/AD · "
                   "<code>[passkey]</code> WebAuthn · <code>[qr]</code> TOTP-QR-Code · "
                   "<code>[redis]</code> Rate-Limit über mehrere Worker. Kombinierbar: "
                   "<code>[oidc,argon2]</code>. Ganz ohne Extra bleiben Passwort + TOTP "
                   "(stdlib-scrypt)."),
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
        "l_account": "Konto", "l_admin": "Admin-Panel", "l_logout": "Abmelden",
        "l_login": "Anmelden", "l_register": "Registrieren", "l_light": "Hell", "l_dark": "Dunkel",
    },
}



LABELS = {
    lang: Labels(account=T[lang]["l_account"], admin=T[lang]["l_admin"], logout=T[lang]["l_logout"],
                 login=T[lang]["l_login"], register=T[lang]["l_register"], docs=T[lang]["cta_docs"],
                 theme_light=T[lang]["l_light"], theme_dark=T[lang]["l_dark"],
                 changelog=T[lang]["f_changelog"], security=T[lang]["f_security"],
                 license=T[lang]["f_license"], credits=T[lang]["credits"])
    for lang in LANGS
}


def site_nav(lang: str) -> Nav:
    t = T[lang]
    return Nav(brand_href=page_url("index", lang), icon_url="wizard.png", repo=REPO,
               pages=((page_url("index", lang), t["nav_overview"]),
                      (page_url("flows", lang), t["nav_flows"])))


def site_ctx(page: str, lang: str, **kw) -> Ctx:
    return Ctx(lang=lang, labels=LABELS[lang], path=page_url(page, lang),
               lang_hrefs={c: page_url(page, c) for c in LANGS}, **kw)


_INDEX_CSS = """
  .wrap{max-width:720px;margin:0 auto;padding:0 22px}
  main{max-width:720px;padding:0 0 24px}
  :root{--nav-w:720px}
  .hero{text-align:center;padding:24px 22px 8px}
  .badge{position:relative;display:inline-grid;place-items:center;width:132px;height:132px;margin-bottom:10px}
  .badge::before{content:"";position:absolute;inset:-18%;border-radius:50%;
    background:radial-gradient(circle at 50% 42%,var(--glow),transparent 68%);z-index:0}
  .badge img{position:relative;z-index:1;width:112px;height:112px;display:block}
  .hero h1{font-family:var(--ts-serif);font-weight:600;font-size:50px;letter-spacing:-.01em;
    margin:.1em 0 .12em;text-wrap:balance}
  .hero h1 .tiny{color:var(--accent)}
  .tagline{color:var(--muted);font-size:18px;max-width:42ch;margin:0 auto;text-wrap:balance}
  .pos{max-width:46ch;margin:14px auto 0;padding:11px 15px;font-size:14px;color:var(--muted);
    background:var(--chip);border:1px solid var(--line);border-radius:10px;text-wrap:balance}
  .pos b{color:var(--ink);font-weight:600}
  .cta{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin:26px 0 6px}
  .note{color:var(--muted);font-size:13.5px}
  .rule{height:1px;background:var(--line);border:0;margin:80px 0}
  section{margin:112px 0}
  section:first-of-type{margin-top:72px}
  h2{font-size:18px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
    font-weight:600;margin:0 0 32px}
  .chips{display:flex;flex-wrap:wrap;gap:8px}
  .chip{background:var(--chip);border:1px solid var(--line);border-radius:999px;padding:6px 13px;
    font-size:14px;color:var(--ink)}
  .chip b{color:var(--accent);font-weight:600}
  .solves{list-style:none;padding:0;margin:0;display:grid;gap:12px}
  .solves li{display:grid;grid-template-columns:auto 1fr;gap:12px;align-items:start;font-size:16px}
  .solves .yes{color:var(--accent);font-weight:700;font-family:var(--ts-serif)}
  .solves b{font-weight:600}
  .solves span{color:var(--muted)}
  .code{background:var(--code-bg);color:var(--code-fg);border-radius:12px;padding:16px 18px;
    overflow-x:auto;font-family:var(--ts-mono);font-size:13.5px;line-height:1.7}
  .code .c{color:#9b93ab}.code .k{color:var(--accent-2)}.code .s{color:#c9a98f}
  .feat{display:grid;grid-template-columns:1fr 1fr;gap:14px 26px}
  .feat div{font-size:15px}
  .feat b{display:block;font-size:15px}
  .feat span{color:var(--muted);font-size:14px}
  @media (max-width:560px){.feat{grid-template-columns:1fr}.hero h1{font-size:38px}}
  @media (prefers-reduced-motion:no-preference){
    section{animation:rise .5s ease both}
  }
"""

_FLOWS_CSS = """
  h1{font-family:var(--ts-serif);font-weight:600;font-size:48px;letter-spacing:-.01em;
    margin:.1em 0 .2em;text-wrap:balance}
  .lead{color:var(--muted);font-size:18px;max-width:60ch;text-wrap:balance}
  .rule{height:1px;background:var(--line);border:0;margin:80px 0}
"""


def hero(lang: str) -> str:
    t = T[lang]
    return (f'<div class=hero><div class="badge">'
            f'<img src="wizard.png" alt="TinySesam" width="112" height="112"></div>'
            f'<h1><span class="tiny">Tiny</span>Sesam</h1>'
            f'<p class="tagline">{t["tagline"]}</p><p class="pos">{t["pos"]}</p>'
            f'<div class="cta">'
            f'<a class="btn primary" id="cta-github" href="{REPO}">{icon("github")}{t["cta_github"]}</a>'
            f'<a class="btn ghost" id="cta-docs" href="{REPO}#readme">{icon("book")}{t["cta_docs"]}</a>'
            f'</div><p class="note">{t["meta"]}</p></div>')


def render_index(lang: str = "en", ctx: Ctx = None, nav: Nav = None) -> str:
    """Überblick. Der Titelbereich ersetzt die Marke — der einzige Sonderfall."""
    t = T[lang]
    ctx = ctx or site_ctx("index", lang)
    ctx.hero = hero(lang)
    nav = nav or site_nav(lang)
    solves = "".join(f'<li><span class="yes">✓</span><span><b>{q}</b><br />— {a}</span></li>'
                     for q, a in t["solves"])
    chips = "".join(f'<span class="chip">{c}</span>' for c in t["chips"])
    feat = "".join(f"<div><b>{h}</b><span>{d}</span></div>" for h, d in t["feat"])
    body = f"""<div class="wrap">
  <section><h2>{t["h_solves"]}</h2><ul class="solves">{solves}</ul></section>

  <section><h2>{t["h_ways"]}</h2><div class="chips">{chips}</div>
    <p class="note" style="margin-top:16px"><a href="{page_url("flows", lang)}">{t["flows_link"]}</a></p>
  </section>

  <section><h2>{t["h_more"]}</h2><div class="feat">{feat}</div></section>

  <section><h2>{t["h_install"]}</h2>
    <div class="code">pip install <span class="s">"tinysesam[all] @ git+{REPO}.git"</span></div>
    <p class="note" style="margin-top:14px">{t["extras"]}</p>
  </section>

  <section><h2>{t["h_use"]}</h2>
    <div class="code"><span class="k">auth</span> = TinySesam(TinySesamConfig(db_path=<span class="s">"app.db"</span>))
app.include_router(<span class="k">auth</span>.router())          <span class="c">{t["use_comment_router"]}</span>

<span class="k">@app</span>.get(<span class="s">"/"</span>)
<span class="k">def</span> home(user = Depends(<span class="k">auth</span>.require_user)):   <span class="c">{t["use_comment_guard"]}</span>
    <span class="k">return</span> {{<span class="s">"hi"</span>: user[<span class="s">"username"</span>]}}</div>
    <p class="note" style="margin-top:14px">{t["gateway"]}</p>
  </section>
</div>"""
    return document(ctx, nav, title=t["title"], desc=t["desc"], css=_INDEX_CSS, body=body)


def render_flows(lang: str = "en", ctx: Ctx = None, nav: Nav = None) -> str:
    t = T[lang]
    ctx = ctx or site_ctx("flows", lang)
    nav = nav or site_nav(lang)
    body = (f'<h1>{t["flows_h1"]}</h1><p class="lead">{t["flows_lead"]}</p><hr class="rule">'
            f'{render_flow_list(lang, cfg=None)}<hr class="rule">'
            f'<p class="lead">{t["flows_outro"]}</p>')
    return document(ctx, nav, title=t["flows_title"], desc=t["flows_desc"],
                    css=_FLOWS_CSS + FLOW_CSS, body=body)


def build_pages() -> dict:
    out = {}
    for lang in LANGS:
        out[page_url("index", lang)] = render_index(lang)
        out[page_url("flows", lang)] = render_flows(lang)
    return out

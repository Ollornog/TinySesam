"""Die Projekt-Website — eine Quelle, zwei Sprachen, zwei Seiten.

    index.html   → Überblick
    flows.html   → alle Login-Wege als Diagramm (Inhalt: web/flows.py)

**Ein** Sprachsystem: `?lang=de` bzw. `?lang=en` schaltet, das Cookie `ts_lang` merkt — genauso wie in
der App. Weil GitHub Pages keinen Server hat, trägt jede Datei **beide** Sprachen und blendet eine aus.
Keine Sprach-Dateinamen.

`web/build.py` schreibt die vier Dateien für GitHub Pages (die Action baut sie bei jedem Push).
Die Demo rendert dieselben Funktionen zur Laufzeit — sie braucht keine gebauten Dateien.

Hier stehen nur **Texte und Seiteninhalt**. Kopf, Navigation und Fußzeile kommen aus `web/ui.py`,
damit Website, Demo und die eingebauten TinySesam-Seiten denselben Rumpf tragen.
"""
from .demo import DEMO_CSS, demo_body, static_src
from .flows import CSS as FLOW_CSS, render as render_flow_list
from .ui import Ctx, Labels, Nav, LANGS, codeblock, icon, shell, static_document

REPO = "https://github.com/Ollornog/TinySesam"

INDEX, FLOWS, LEGAL, DEMO = "index.html", "flows.html", "legal.html", "demo.html"

# Anbieterkennzeichnung der Projektseite. § 5 DDG (seit 14.05.2025, löste § 5 TMG ab) verlangt
# Name, ladungsfähige Anschrift und einen schnellen elektronischen Kontakt.
OWNER = {
    "name": "Daniel Brunthaler",
    "street": "Hebbelstraße 22",
    "city": "23843 Bad Oldesloe",
    "country": "Deutschland",
    "email": "tinysesam-github@ollornog.de",
}

# Für welche Adresse gilt dieses Impressum? Nur für die offizielle Projektseite. Wer den Code
# selbst hostet, ist selbst Anbieter — TinySesam ist eine Vorlage, kein Angebot des Autors.
SITE_URL = "ollornog.github.io/TinySesam"
# ────────────────────────────────────────────────────────────────────────────────
LANG_HREFS = {c: f"?lang={c}" for c in LANGS}   # eine URL je Seite, die Sprache ist ein Parameter


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
        "copy": "Copy", "copied": "Copied",
        "extras_intro": "<code>[all]</code> pulls every optional dependency. Take only what you need:",
        "extras": [
            ("argon2", "stronger hashing"),
            ("oidc", "OIDC login"),
            ("saml", "SAML&nbsp;2.0"),
            ("ldap", "LDAP/AD"),
            ("passkey", "WebAuthn"),
            ("qr", "TOTP&nbsp;QR code"),
            ("redis", "rate limit across workers"),
        ],
        "extras_outro": ("Combine them: <code>[oidc,argon2]</code>. Without any extra you still "
                         "get password + TOTP (stdlib scrypt)."),
        "use_comment_router": "# /auth/* + login UI", "use_comment_guard": "# protected",
        "gateway": ('Want just SSO in front of existing apps? Run it as an '
                    f'<a href="{REPO}#as-a-pure-oidc-gateway-preset">OIDC forward-auth gateway</a>.'),
        "f_changelog": "Changelog", "f_security": "Security", "f_license": "MIT License",
        "f_legal": "Legal notice",
        "legal_title": "TinySesam — legal notice & privacy",
        "legal_desc": "Imprint under § 5 DDG and privacy information for the TinySesam project page.",
        "legal_h1": "Legal notice & privacy",
        "legal_lead": "This page is the documentation of a non-commercial open-source project. "
                      "It shows no ads, tracks nobody and loads nothing from third-party hosts.",
        "l_imprint": "Imprint",
        "l_imprint_note": "Information under § 5 DDG (which replaced § 5 TMG on 14 May 2025) and "
                          "responsible for the content under § 18 (2) MStV.",
        "l_privacy": "Privacy",
        "l_hosting_h": "Hosting on GitHub Pages",
        "l_hosting": "This page is served by GitHub Pages (GitHub, Inc., 88 Colin P. Kelly Jr. St, "
                     "San Francisco, CA 94107, USA). GitHub writes server log files for every request: "
                     "IP address, time, requested file, referrer, browser and operating system. "
                     "<b>This happens at GitHub, on GitHub's systems — the operator of this page neither "
                     "receives nor stores those logs and cannot hand them out.</b> Legal basis is "
                     "Art. 6 (1) (f) GDPR — the legitimate interest in serving the page securely and "
                     "reliably. GitHub processes data in the USA and is certified under the EU-US Data "
                     "Privacy Framework. What GitHub does with the data is described in its "
                     '<a href="https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement">'
                     "privacy statement</a>; direct requests about those logs to GitHub.",
        "l_browser_h": "What is stored in your browser",
        "l_browser": "Two things, both because you asked for them, neither for tracking: the cookie "
                     "<code>ts_lang</code> remembers the language you picked, and "
                     "<code>localStorage['ts-theme']</code> remembers light or dark mode. No analytics, "
                     "no third-party cookies, no fonts or scripts from other hosts — which is why there "
                     "is no cookie banner.",
        "l_controller_h": "Who is responsible for what",
        "l_controller": "Responsible for the <i>content</i> of this page is the person named in the "
                        "imprint — they decided to publish it. Responsible for the <i>server</i> is "
                        "GitHub: it runs the machines, writes the logs and decides how long to keep them. "
                        "This page itself collects nothing, has no database, no analytics and no contact "
                        "form. Requests about the logs therefore have to go to GitHub; requests about "
                        "this page's content go to the address above.",
        "l_rights_h": "Your rights",
        "l_rights": "Art. 15–21 GDPR give you the right to information, correction, deletion, "
                    "restriction, portability and objection — always <b>towards whoever actually holds "
                    "the data</b>. Server logs are held by GitHub, so requests about them belong there. "
                    "The operator of this page holds nothing: no database, no logs, no addresses, no "
                    "backups. There is simply nothing to disclose or delete. What your browser stores "
                    "(see above) never leaves your device — clearing your browser data removes it. "
                    "You may complain to a supervisory authority at any time.",
        "l_scope_h": "What this notice covers",
        "l_scope": "This imprint applies to the project page at <code>{url}</code> and nothing else. "
                   "TinySesam is free software under the MIT licence — a template. Whoever installs it "
                   "on their own server operates their own service, is its provider, and answers for it "
                   "themselves. The author of the software has nothing to do with those installations.",
        "l_liability_h": "Links",
        "l_liability": "This page links to external sites. Their content is the responsibility of their "
                       "operators; at the time of linking nothing unlawful was apparent.",
        "credits": '<a href="https://www.flaticon.com/free-icons/wizard" title="wizard icons">'
                   'Wizard icons created by max.icons — Flaticon</a>',
        # Demo-Seite
        "demo_title": "TinySesam — demo",
        "demo_desc": "The login page, the account page and the admin panel of TinySesam, "
                     "rendered from the library itself.",
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
        "nav_overview": "Overview", "nav_flows": "Sign-in flows", "nav_demo": "Demo",
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
        "copy": "Kopieren", "copied": "Kopiert",
        "extras_intro": "<code>[all]</code> zieht alle optionalen Abhängigkeiten. Nimm nur, was du brauchst:",
        "extras": [
            ("argon2", "stärkeres Hashing"),
            ("oidc", "OIDC-Login"),
            ("saml", "SAML&nbsp;2.0"),
            ("ldap", "LDAP/AD"),
            ("passkey", "WebAuthn"),
            ("qr", "TOTP-QR-Code"),
            ("redis", "Rate-Limit über mehrere Worker"),
        ],
        "extras_outro": ("Kombinierbar: <code>[oidc,argon2]</code>. Ganz ohne Extra bleiben "
                         "Passwort + TOTP (stdlib-scrypt)."),
        "use_comment_router": "# /auth/* + Login-UI", "use_comment_guard": "# geschützt",
        "gateway": ('Nur SSO vor bestehende Apps? Dann als '
                    f'<a href="{REPO}#as-a-pure-oidc-gateway-preset">OIDC-Forward-Auth-Gateway</a> betreiben.'),
        "f_changelog": "Changelog", "f_security": "Sicherheit", "f_license": "MIT-Lizenz",
        "f_legal": "Impressum",
        "legal_title": "TinySesam — Impressum & Datenschutz",
        "legal_desc": "Impressum nach § 5 DDG und Datenschutzhinweise für die Projektseite von TinySesam.",
        "legal_h1": "Impressum & Datenschutz",
        "legal_lead": "Diese Seite ist die Dokumentation eines nicht-kommerziellen Open-Source-Projekts. "
                      "Sie zeigt keine Werbung, verfolgt niemanden und lädt nichts von fremden Servern.",
        "l_imprint": "Impressum",
        "l_imprint_note": "Angaben gemäß § 5 DDG (löste am 14.05.2025 den § 5 TMG ab) und "
                          "verantwortlich für den Inhalt nach § 18 Abs. 2 MStV.",
        "l_privacy": "Datenschutz",
        "l_hosting_h": "Hosting bei GitHub Pages",
        "l_hosting": "Diese Seite wird von GitHub Pages ausgeliefert (GitHub, Inc., 88 Colin P. Kelly Jr. "
                     "St, San Francisco, CA 94107, USA). GitHub schreibt bei jedem Aufruf Server-Logs: "
                     "IP-Adresse, Zeitpunkt, angefragte Datei, Referrer, Browser und Betriebssystem. "
                     "<b>Das passiert bei GitHub, auf GitHubs Systemen — der Betreiber dieser Seite "
                     "bekommt diese Logs weder zu sehen noch kann er sie herausgeben.</b> Rechtsgrundlage "
                     "ist Art. 6 Abs. 1 lit. f DSGVO — das berechtigte Interesse, die Seite sicher und "
                     "zuverlässig auszuliefern. GitHub verarbeitet Daten in den USA und ist unter dem "
                     "EU-US Data Privacy Framework zertifiziert. Was GitHub mit den Daten tut, steht in "
                     'seiner <a href="https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement">'
                     "Datenschutzerklärung</a>; Anfragen zu diesen Logs richte bitte direkt an GitHub.",
        "l_browser_h": "Was in deinem Browser gespeichert wird",
        "l_browser": "Zwei Dinge, beide weil du sie angefordert hast, keines zum Verfolgen: das Cookie "
                     "<code>ts_lang</code> merkt sich die gewählte Sprache, "
                     "<code>localStorage['ts-theme']</code> merkt sich hell oder dunkel. Keine Statistik, "
                     "keine Fremd-Cookies, keine Schriften oder Skripte von anderen Servern — deshalb gibt "
                     "es hier auch kein Cookie-Banner.",
        "l_controller_h": "Wer wofür verantwortlich ist",
        "l_controller": "Für den <i>Inhalt</i> dieser Seite ist die im Impressum genannte Person "
                        "verantwortlich — sie hat entschieden, ihn zu veröffentlichen. Für den "
                        "<i>Server</i> ist GitHub verantwortlich: dort laufen die Maschinen, dort "
                        "entstehen die Logs, dort wird über deren Aufbewahrung entschieden. Diese Seite "
                        "selbst erhebt nichts, hat keine Datenbank, keine Statistik und kein "
                        "Kontaktformular. Anfragen zu den Logs müssen daher an GitHub gehen; Anfragen "
                        "zum Inhalt dieser Seite an die Adresse oben.",
        "l_rights_h": "Deine Rechte",
        "l_rights": "Art. 15–21 DSGVO geben dir Auskunft, Berichtigung, Löschung, Einschränkung, "
                    "Übertragung und Widerspruch — immer gegenüber dem, <b>der die Daten tatsächlich "
                    "hat</b>. Die Server-Logs hat GitHub, dorthin gehören Anfragen dazu. Der Betreiber "
                    "dieser Seite hat nichts: keine Datenbank, keine Logs, keine Adressen, keine "
                    "Sicherungen. Es gibt schlicht nichts, worüber Auskunft zu geben oder was zu löschen "
                    "wäre. Was dein Browser speichert (siehe oben), verlässt dein Gerät nie — Browserdaten "
                    "löschen genügt. Eine Beschwerde bei einer Aufsichtsbehörde steht dir jederzeit offen.",
        "l_scope_h": "Wofür dieser Hinweis gilt",
        "l_scope": "Dieses Impressum gilt für die Projektseite unter <code>{url}</code> und für sonst "
                   "nichts. TinySesam ist freie Software unter der MIT-Lizenz — eine Vorlage. Wer sie auf "
                   "einem eigenen Server installiert, betreibt einen eigenen Dienst, ist dessen Anbieter "
                   "und haftet selbst dafür. Mit solchen Installationen hat der Autor der Software nichts "
                   "zu tun.",
        "l_liability_h": "Links",
        "l_liability": "Diese Seite verlinkt auf fremde Seiten. Für deren Inhalte sind deren Betreiber "
                       "verantwortlich; zum Zeitpunkt der Verlinkung war nichts Rechtswidriges erkennbar.",
        "credits": '<a href="https://www.flaticon.com/free-icons/wizard" title="wizard icons">'
                   'Wizard icons created by max.icons — Flaticon</a>',
        "demo_title": "TinySesam — Demo",
        "demo_desc": "Die Anmeldeseite, die Konto-Seite und das Admin-Panel von TinySesam, "
                     "gerendert aus der Bibliothek selbst.",
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
        "nav_overview": "Überblick", "nav_flows": "Login-Flows", "nav_demo": "Demo",
        "l_account": "Konto", "l_admin": "Admin-Panel", "l_logout": "Abmelden",
        "l_login": "Anmelden", "l_register": "Registrieren", "l_light": "Hell", "l_dark": "Dunkel",
    },
}



LABELS = {
    lang: Labels(account=T[lang]["l_account"], admin=T[lang]["l_admin"], logout=T[lang]["l_logout"],
                 login=T[lang]["l_login"], register=T[lang]["l_register"], docs=T[lang]["cta_docs"],
                 theme_light=T[lang]["l_light"], theme_dark=T[lang]["l_dark"],
                 changelog=T[lang]["f_changelog"], security=T[lang]["f_security"],
                 license=T[lang]["f_license"], legal=T[lang]["f_legal"], credits=T[lang]["credits"])
    for lang in LANGS
}


def site_nav(lang: str) -> Nav:
    t = T[lang]
    return Nav(brand_href=INDEX, icon_url="wizard.png", repo=REPO, flows_href=FLOWS,
               legal_href=LEGAL,
               pages=((INDEX, t["nav_overview"]), (DEMO, t["nav_demo"]), (FLOWS, t["nav_flows"])))


def site_ctx(page: str, lang: str, **kw) -> Ctx:
    return Ctx(lang=lang, labels=LABELS[lang], path=page, lang_hrefs=LANG_HREFS, **kw)


INDEX_CSS = """
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
  /* Grid auf der Liste, `li{display:contents}` — sonst ist jedes li sein eigenes Raster
     und die Beschreibungen fluchten nicht. */
  /* Eine Schriftgröße für den ganzen Block: `code` schrumpft global auf .86em, die Beschreibung
     nicht — nebeneinander sähen sie ungleich aus. Beide auf die kleinere Größe (wie `.note`). */
  .extras{list-style:none;padding:0;margin:12px 0;display:grid;
          grid-template-columns:auto 1fr;gap:8px 14px;align-items:baseline;font-size:13.5px}
  .extras li{display:contents}
  .extras code{justify-self:start;font-size:1em}
  .extras span{color:var(--muted)}
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


def index_body(lang: str, nav: Nav) -> str:
    """Der Inhalt der Startseite (ohne Rumpf)."""
    t = T[lang]
    solves = "".join(f'<li><span class="yes">✓</span><span><b>{q}</b><br />— {a}</span></li>'
                     for q, a in t["solves"])
    chips = "".join(f'<span class="chip">{c}</span>' for c in t["chips"])
    feat = "".join(f"<div><b>{h}</b><span>{d}</span></div>" for h, d in t["feat"])
    extras = "".join(f'<li><code>[{name}]</code><span>{desc}</span></li>' for name, desc in t["extras"])
    code = lambda inner: codeblock(inner, copy=t["copy"], copied=t["copied"])  # noqa: E731

    install = code(f'pip install <span class="s">"tinysesam[all] @ git+{REPO}.git"</span>')
    use = code(
        f'<span class="k">auth</span> = TinySesam(TinySesamConfig(db_path=<span class="s">"app.db"</span>))\n'
        f'app.include_router(<span class="k">auth</span>.router())'
        f'          <span class="c">{t["use_comment_router"]}</span>\n\n'
        f'<span class="k">@app</span>.get(<span class="s">"/"</span>)\n'
        f'<span class="k">def</span> home(user = Depends(<span class="k">auth</span>.require_user)):'
        f'   <span class="c">{t["use_comment_guard"]}</span>\n'
        f'    <span class="k">return</span> {{<span class="s">"hi"</span>: user[<span class="s">"username"</span>]}}')

    return f"""<div class="wrap">
  <section><h2>{t["h_solves"]}</h2><ul class="solves">{solves}</ul></section>

  <section><h2>{t["h_ways"]}</h2><div class="chips">{chips}</div>
    <p class="note" style="margin-top:16px"><a href="{nav.flows_href}">{t["flows_link"]}</a></p>
  </section>

  <section><h2>{t["h_more"]}</h2><div class="feat">{feat}</div></section>

  <section><h2>{t["h_install"]}</h2>
    {install}
    <p class="note" style="margin-top:14px">{t["extras_intro"]}</p>
    <ul class="extras">{extras}</ul>
    <p class="note">{t["extras_outro"]}</p>
  </section>

  <section><h2>{t["h_use"]}</h2>
    {use}
    <p class="note" style="margin-top:14px">{t["gateway"]}</p>
  </section>
</div>"""


LEGAL_CSS = """
  h1{font-family:var(--ts-serif);font-weight:600;font-size:48px;letter-spacing:-.01em;
    margin:.1em 0 .2em;text-wrap:balance}
  .lead{color:var(--muted);font-size:18px;text-wrap:balance}
  section{margin:64px 0}
  h2{font-size:18px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
    font-weight:600;margin:0 0 20px}
  h3{font-family:var(--ts-serif);font-size:22px;margin:32px 0 8px}
  address{font-style:normal;background:var(--chip);border:1px solid var(--line);border-radius:12px;
    padding:16px 18px;line-height:1.7;display:inline-block}
  .todo{color:var(--danger);font-weight:600}
"""


def legal_body(lang: str) -> str:
    """Impressum + Datenschutz. Die Angaben stehen in `OWNER` — Platzhalter fallen sofort auf."""
    t = T[lang]
    def field(key):
        v = OWNER[key]
        return f'<span class=todo>{v}</span>' if v.startswith("«") else v
    return f"""
  <h1>{t["legal_h1"]}</h1>
  <p class="lead">{t["legal_lead"]}</p>

  <section><h2>{t["l_imprint"]}</h2>
    <p>{t["l_imprint_note"]}</p>
    <address>{field("name")}<br>{field("street")}<br>{field("city")}<br>{field("country")}<br>
      <a href="mailto:{OWNER["email"]}">{OWNER["email"]}</a></address>
    <h3>{t["l_scope_h"]}</h3><p>{t["l_scope"].format(url=SITE_URL)}</p>
  </section>

  <section><h2>{t["l_privacy"]}</h2>
    <h3>{t["l_controller_h"]}</h3><p>{t["l_controller"]}</p>
    <h3>{t["l_hosting_h"]}</h3><p>{t["l_hosting"]}</p>
    <h3>{t["l_browser_h"]}</h3><p>{t["l_browser"]}</p>
    <h3>{t["l_rights_h"]}</h3><p>{t["l_rights"]}</p>
    <h3>{t["l_liability_h"]}</h3><p>{t["l_liability"]}</p>
  </section>"""


def flows_body(lang: str) -> str:
    t = T[lang]
    return (f'<h1>{t["flows_h1"]}</h1><p class="lead">{t["flows_lead"]}</p><hr class="rule">'
            f'{render_flow_list(lang, cfg=None)}<hr class="rule">'
            f'<p class="lead">{t["flows_outro"]}</p>')


# Die App rendert dieselben Seiten serverseitig — sie kennt die Sprache schon.
def render_index(lang: str, ctx: Ctx, nav: Nav) -> str:
    ctx.hero = hero(lang)
    return shell(ctx, nav, index_body(lang, nav))


def render_flows(lang: str, ctx: Ctx, nav: Nav) -> str:
    return shell(ctx, nav, flows_body(lang))


def render_legal(lang: str, ctx: Ctx, nav: Nav) -> str:
    return shell(ctx, nav, legal_body(lang))


def demo_page_body(lang: str) -> str:
    """Die Demo-Seite, statisch: die Frames zeigen auf die zur Bauzeit gerenderten Panels."""
    return demo_body(lang, src=static_src(lang))


def build_pages() -> dict:
    """Vier Dateien, alle zweisprachig. Die Sprache wählt `?lang=`/Cookie — nicht der Dateiname."""
    nav = site_nav(LANGS[0])
    out = {}
    for name, page, css, body_of, title_key, desc_key in (
            (INDEX, "index", INDEX_CSS, lambda l: index_body(l, nav), "title", "desc"),
            (DEMO, "demo", _FLOWS_CSS + DEMO_CSS, demo_page_body, "demo_title", "demo_desc"),
            (FLOWS, "flows", _FLOWS_CSS + FLOW_CSS, flows_body, "flows_title", "flows_desc"),
            (LEGAL, "legal", LEGAL_CSS, legal_body, "legal_title", "legal_desc")):
        variants = {}
        for lang in LANGS:
            ctx = site_ctx(page, lang)
            if page == "index":
                ctx.hero = hero(lang)
            variants[lang] = (T[lang][title_key], T[lang][desc_key],
                              shell(ctx, site_nav(lang), body_of(lang)))
        out[name] = static_document(nav, css, variants)
    return out

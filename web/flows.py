"""Die Login-Wege als Diagramm — EINE Quelle für zwei Ausgaben.

* Die Demo rendert sie unter `/demo/flows` und markiert, was in ihrer Config aktiv ist.
* `tools/build_flows.py` backt daraus `docs/flows.html` für GitHub Pages (statisch, ohne Server);
  dort steht statt der Markierung der Config-Schalter, mit dem man den Weg einschaltet.

Kein FastAPI-Import — deshalb kann der Generator die Datei ohne laufende App benutzen.
"""

# Jeder Weg: Kette aus Kästchen (do = du tust etwas, srv = TinySesam, end = Ergebnis),
# der Config-Schalter, und ein Hinweis. `note` darf eine Funktion sein: note(cfg) mit cfg=None
# für die statische Seite.
FLOWS = [
    {
        "key": "password",
        "config": "password_enabled=True",
        "active": lambda c: "password" in c.enabled_methods(),
        "de": {
            "title": "Passwort",
            "why": "Der klassische Weg. Ein Erstfaktor genügt, solange keine Kette gesetzt ist.",
            "steps": [("do", "Kennung + Passwort"), ("srv", "<code>/auth/login</code>"),
                      ("end", "Sitzung"), ("end", "geschützte Route")],
            "note": lambda c: (
                "Das Kennungsfeld folgt <code>login_identifier</code>: Benutzername, E-Mail oder beides."
                if c is None else
                f"Das Kennungsfeld akzeptiert hier: <b>{_IDENT_DE[c.login_identifier]}</b>."),
        },
        "en": {
            "title": "Password",
            "why": "The classic route. One first factor is enough unless you configure a chain.",
            "steps": [("do", "identifier + password"), ("srv", "<code>/auth/login</code>"),
                      ("end", "session"), ("end", "protected route")],
            "note": lambda c: (
                "The identifier field follows <code>login_identifier</code>: username, email or both."
                if c is None else
                f"Here the field accepts: <b>{_IDENT_EN[c.login_identifier]}</b>."),
        },
    },
    {
        "key": "pin",
        "config": "pin_enabled=True, pin_login=True",
        "active": lambda c: "pin" in c.enabled_methods(),
        "de": {
            "title": "PIN als Erstfaktor",
            "why": "Statt Passwort mit einer kurzen PIN anmelden — mit eigenem, strengerem Lockout.",
            "steps": [("do", "Kennung + PIN"), ("srv", "<code>/auth/pin</code>"), ("end", "Sitzung")],
            "note": "Mit <code>pin_login=False</code> existiert die PIN weiter, ist aber "
                    "<b>kein Login-Weg</b> mehr — nur noch Zusatzfaktor oder Step-up (siehe unten).",
        },
        "en": {
            "title": "PIN as a first factor",
            "why": "Sign in with a short PIN instead of a password — with its own, stricter lockout.",
            "steps": [("do", "identifier + PIN"), ("srv", "<code>/auth/pin</code>"), ("end", "session")],
            "note": "With <code>pin_login=False</code> the PIN still exists but is <b>no way in</b> — "
                    "only an extra factor or a step-up (see below).",
        },
    },
    {
        "key": "totp",
        "config": "totp_enabled=True",
        "active": lambda c: c.totp_enabled,
        "de": {
            "title": "Zweiter Faktor (TOTP)",
            "why": "Nach dem Erstfaktor ein Einmalcode aus der Authenticator-App.",
            "steps": [("do", "Erstfaktor"), ("srv", "<code>/auth/totp</code>"), ("do", "6-stelliger Code"),
                      ("end", "Sitzung <i>mfa_ok</i>")],
            "note": "Wer keine 2FA eingerichtet hat, überspringt den Schritt. Recovery-Codes gehen ebenso. "
                    "<code>totp_required=True</code> macht ihn zur Pflicht.",
        },
        "en": {
            "title": "Second factor (TOTP)",
            "why": "After the first factor, a one-time code from an authenticator app.",
            "steps": [("do", "first factor"), ("srv", "<code>/auth/totp</code>"), ("do", "6-digit code"),
                      ("end", "session <i>mfa_ok</i>")],
            "note": "Users without 2FA skip the step; recovery codes work too. "
                    "<code>totp_required=True</code> makes it mandatory.",
        },
    },
    {
        "key": "stepup",
        "config": 'require(mfa=True), stepup_methods=["pin"]',
        "active": lambda c: True,
        "de": {
            "title": "Step-up für sensible Bereiche",
            "why": "Du bist eingeloggt — der Bereich verlangt trotzdem eine frische Bestätigung.",
            "steps": [("do", "sensible Route"), ("srv", "Frische abgelaufen?"),
                      ("srv", "<code>/auth/reauth</code>"), ("do", "PIN / TOTP / Passwort"),
                      ("end", "Bereich offen")],
            "note": lambda c: (
                "<code>stepup_methods</code> schränkt ein, womit bestätigt werden darf. Leer = das stärkste "
                "Verfahren, das der Nutzer eingerichtet hat (TOTP → PIN → Passwort). Nach "
                "<code>stepup_max_age_sec</code> wird erneut gefragt."
                if c is None else
                f"Hier: <code>stepup_methods={c.stepup_methods}</code>. Leer wäre: das stärkste Verfahren, "
                f"das der Nutzer hat (TOTP → PIN → Passwort). Erneut nach "
                f"<code>stepup_max_age_sec={c.stepup_max_age_sec}</code>."),
        },
        "en": {
            "title": "Step-up for sensitive areas",
            "why": "You are signed in — the area still demands a fresh confirmation.",
            "steps": [("do", "sensitive route"), ("srv", "freshness expired?"),
                      ("srv", "<code>/auth/reauth</code>"), ("do", "PIN / TOTP / password"),
                      ("end", "area unlocked")],
            "note": lambda c: (
                "<code>stepup_methods</code> restricts what may confirm. Empty = the strongest method the "
                "user has set up (TOTP → PIN → password). Asked again after <code>stepup_max_age_sec</code>."
                if c is None else
                f"Here: <code>stepup_methods={c.stepup_methods}</code>. Empty would mean the strongest "
                f"method the user has. Asked again after "
                f"<code>stepup_max_age_sec={c.stepup_max_age_sec}</code>."),
        },
    },
    {
        "key": "chain",
        "config": 'require(factors=["password", "pin"])',
        "active": lambda c: True,
        "de": {
            "title": "Faktor-Kette pro Route",
            "why": "Eine Route verlangt mehrere Faktoren in fester Reihenfolge.",
            "steps": [("do", "Passwort"), ("srv", "Kette unvollständig"), ("srv", "<code>/auth/pin</code>"),
                      ("do", "PIN"), ("end", "Route offen")],
            "note": "Wer schon eingeloggt ist, bekommt nur das fehlende Feld — nicht noch einmal die ganze "
                    "Login-Seite. Global geht dasselbe über <code>login_chain</code>.",
        },
        "en": {
            "title": "Factor chain per route",
            "why": "A route demands several factors in a fixed order.",
            "steps": [("do", "password"), ("srv", "chain incomplete"), ("srv", "<code>/auth/pin</code>"),
                      ("do", "PIN"), ("end", "route unlocked")],
            "note": "Someone already signed in only gets the missing field — not the whole login page again. "
                    "The same works globally via <code>login_chain</code>.",
        },
    },
    {
        "key": "resource",
        "config": "resource_locks_enabled=True",
        "active": lambda c: c.resource_locks_enabled,
        "de": {
            "title": "Geteiltes Geheimnis (ohne Konto)",
            "why": "Ein Bereich, eine PIN oder Passphrase. Keine Registrierung, kein Benutzer.",
            "steps": [("do", "geschützter Bereich"), ("srv", "<code>/auth/resource/&lt;name&gt;</code>"),
                      ("do", "PIN"), ("end", "Bereich offen, zeitlich begrenzt")],
            "note": "<code>Depends(auth.require_resource(\"gaeste\"))</code> — hängt an einem eigenen Cookie, "
                    "nicht an einer Sitzung.",
        },
        "en": {
            "title": "Shared secret (no account)",
            "why": "One area, one PIN or passphrase. No sign-up, no user.",
            "steps": [("do", "protected area"), ("srv", "<code>/auth/resource/&lt;name&gt;</code>"),
                      ("do", "PIN"), ("end", "unlocked, time-limited")],
            "note": "<code>Depends(auth.require_resource(\"guests\"))</code> — backed by its own cookie, "
                    "not by a session.",
        },
    },
    {
        "key": "magic",
        "config": "magiclink_enabled=True + Mailer",
        "active": lambda c: c.magiclink_enabled,
        "de": {
            "title": "Login-Link per E-Mail",
            "why": "Adresse eingeben, Einmal-Link anklicken, drin.",
            "steps": [("do", "E-Mail"), ("srv", "Mailer"), ("do", "Link klicken"), ("end", "Sitzung")],
            "note": "Derselbe Mechanismus trägt Einladungen, Passwort-vergessen und die "
                    "E-Mail-Bestätigung bei der Registrierung.",
        },
        "en": {
            "title": "Sign-in link by email",
            "why": "Type your address, click the one-time link, you are in.",
            "steps": [("do", "email"), ("srv", "mailer"), ("do", "click link"), ("end", "session")],
            "note": "The same mechanism carries invitations, forgot-password and the sign-up "
                    "email confirmation.",
        },
    },
    {
        "key": "idp",
        "config": "oidc_enabled=True / saml_enabled=True",
        "active": lambda c: c.oidc_enabled or c.saml_enabled,
        "de": {
            "title": "Externer IdProvider",
            "why": "OIDC, SAML oder LDAP/AD. TinySesam ist der Client — nicht der Provider.",
            "steps": [("do", "Knopf"), ("srv", "IdP (PocketID, Entra, ADFS …)"), ("srv", "Callback"),
                      ("end", "Sitzung + Rollen aus Gruppen")],
            "note": "Gruppen des IdP lassen sich auf lokale Rollen mappen — danach greifen überall "
                    "dieselben <code>require_role(...)</code>-Guards.",
        },
        "en": {
            "title": "External identity provider",
            "why": "OIDC, SAML or LDAP/AD. TinySesam is the client — not the provider.",
            "steps": [("do", "button"), ("srv", "IdP (PocketID, Entra, ADFS …)"), ("srv", "callback"),
                      ("end", "session + roles from groups")],
            "note": "Map IdP groups onto local roles — after that the same "
                    "<code>require_role(...)</code> guards apply everywhere.",
        },
    },
    {
        "key": "forward",
        "config": "forward_auth_enabled=True",
        "active": lambda c: c.forward_auth_enabled,
        "de": {
            "title": "Forward-Auth (fremde Apps)",
            "why": "Der Reverse-Proxy fragt vor jedem Request nach — so sichert man Apps, die man nicht baut.",
            "steps": [("do", "Request an fremde App"), ("srv", "Proxy → <code>/auth/forward</code>"),
                      ("end", "200 + Remote-User"), ("end", "App antwortet")],
            "note": "Ohne Sitzung: 401 + <code>X-TinySesam-Location</code> → der Proxy schickt zum Login. "
                    "Beispiele für Caddy/nginx/Traefik liegen in <code>deploy/forward-auth/</code>.",
        },
        "en": {
            "title": "Forward-auth (other apps)",
            "why": "The reverse proxy asks before every request — this is how you guard apps you did not build.",
            "steps": [("do", "request to other app"), ("srv", "proxy → <code>/auth/forward</code>"),
                      ("end", "200 + Remote-User"), ("end", "app responds")],
            "note": "Without a session: 401 + <code>X-TinySesam-Location</code> → the proxy redirects to login. "
                    "Caddy/nginx/Traefik examples live in <code>deploy/forward-auth/</code>.",
        },
    },
]

_IDENT_DE = {"username": "Benutzername", "email": "E-Mail", "both": "Benutzername oder E-Mail"}
_IDENT_EN = {"username": "username", "email": "email", "both": "username or email"}

TEXT = {
    "de": {"legend_do": "du tust etwas", "legend_srv": "TinySesam", "legend_end": "Ergebnis",
           "on": "in dieser Demo aktiv", "off": "hier aus"},
    "en": {"legend_do": "you do something", "legend_srv": "TinySesam", "legend_end": "result",
           "on": "on", "off": "off"},
}

CSS = """
.legend{display:flex;gap:20px;flex-wrap:wrap;margin-top:22px;color:var(--muted);font-size:14px}
.legend span{display:flex;align-items:center;gap:8px}
.legend i.box{width:16px;height:16px;padding:0;display:inline-block}
.flow{margin:0 0 72px}
.flowhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.flowhead h3{font-family:var(--ts-serif);font-size:26px;margin:0;padding-top:8px}
.pill{font-size:12px;padding:2px 10px;border-radius:999px;border:1px solid var(--line)}
.pill.on{background:var(--ok-bg);color:var(--ok-ink);border-color:transparent}
.pill.off{background:var(--chip);color:var(--muted)}
.pill.cfg{background:var(--chip);color:var(--muted);font-family:var(--ts-mono);font-size:11.5px}
.flow>.muted{margin:8px 0 0;color:var(--muted);font-size:15.5px}
.chain{list-style:none;display:flex;align-items:center;flex-wrap:wrap;gap:8px;padding:0;margin:16px 0 0}
.chain li{display:flex}
.chain .arr{color:var(--muted);font-size:18px}
.box{display:inline-block;padding:8px 13px;border-radius:10px;font-size:14px;line-height:1.35;
  border:1px solid var(--line);background:var(--card)}
.box code{background:none;border:0;padding:0;font-size:.92em}
.box.do{border-color:var(--accent)}
.box.srv{background:var(--chip)}
.box.end{background:var(--ok-bg);color:var(--ok-ink);border-color:transparent}
.flow .note{margin:12px 0 0;color:var(--muted);font-size:14px;max-width:70ch}
"""


def chain(steps) -> str:
    out = []
    for i, (kind, text) in enumerate(steps):
        if i:
            out.append("<li class=arr aria-hidden=true>&rarr;</li>")
        out.append(f"<li><span class='box {kind}'>{text}</span></li>")
    return f"<ol class=chain>{''.join(out)}</ol>"


def render(lang="de", cfg=None) -> str:
    """Alle Flows als HTML. `cfg` gesetzt → Markierung aktiv/aus; `cfg=None` → Config-Schalter."""
    t = TEXT[lang]
    parts = [
        f"<div class=legend><span><i class='box do'></i> {t['legend_do']}</span>"
        f"<span><i class='box srv'></i> {t['legend_srv']}</span>"
        f"<span><i class='box end'></i> {t['legend_end']}</span></div><hr class=rule>"
    ]
    for f in FLOWS:
        loc = f[lang]
        if cfg is None:
            pill = f"<span class='pill cfg'>{f['config']}</span>"
        else:
            on = f["active"](cfg)
            pill = f"<span class='pill {'on' if on else 'off'}'>{t['on'] if on else t['off']}</span>"
        note = loc["note"]
        note = note(cfg) if callable(note) else note
        parts.append(
            f"<section class=flow><div class=flowhead><h3>{loc['title']}</h3>{pill}</div>"
            f"<p class=muted>{loc['why']}</p>{chain(loc['steps'])}"
            f"<p class=note>{note}</p></section>")
    return "".join(parts)

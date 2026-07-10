"""Die Demo-Seite — an einer Stelle, für zwei Ausgaben.

* `examples/showcase.py` rendert sie **live** unter `/demo` und liefert die Vorschauen
  aus eigenen Routen.
* `web.build` backt sie **statisch** nach `demo.html` + `demo/*.html` für GitHub Pages,
  wo kein Serverprozess läuft.

Beide benutzen dieselbe Config (`demo_config`), dieselben Beispieldaten (`MOCK`) und
denselben Rahmen (`shot`, `DEMO_CSS`, `FIT_JS`) — sonst driften Schaufenster und Website
auseinander, und genau das ist schon passiert.

`tinysesam` wird **erst in den Funktionen importiert**, die es brauchen (`demo_config`,
`render_previews`, `build`). Texte, CSS und der Seitenrumpf bleiben dadurch importierbar,
ohne dass FastAPI installiert ist — `site.py` baut die Website weiterhin aus der reinen
Standardbibliothek.

Die statischen Panels entstehen gegen eine **In-Memory-Datenbank** (`db_path=":memory:"`):
kein temporäres File, nichts aufzuräumen. Angezeigt werden ausschließlich die hartkodierten
Beispieldaten unten — es wird nichts geseedet.
"""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from .ui import LANGS, UI_CSS

# ---------------------------------------------------------------- Beispieldaten
# Was das Admin-Panel in der Vorschau anzeigt. Es holt sie per `fetch` von `<base>/api/…`;
# live antwortet eine lesende Attrappen-Route, statisch liegen sie als Dateien daneben.
# IP nach RFC 5737 (Dokumentationsbereich) — der Hygiene-Test verbietet echte Adressen.
MOCK = {
    "users": [
        {"id": 1, "username": "demoadmin", "is_admin": True, "is_service": False, "roles": [], "disabled": False},
        {"id": 2, "username": "demo", "is_admin": False, "is_service": False, "roles": ["editor"], "disabled": False},
        {"id": 3, "username": "martin", "is_admin": False, "is_service": False, "roles": ["viewer"], "disabled": True},
        {"id": 4, "username": "backup-daemon", "is_admin": False, "is_service": True, "roles": ["reader"], "disabled": False},
    ],
    "sessions": [{"id": 1, "username": "demoadmin", "method": "password", "ip": "203.0.113.7",
                  "created": 1_770_000_000, "expires": 1_770_600_000}],
    "security": {"max_login_attempts": 5, "lockout_window_sec": 900, "rate_limit_max": 30},
    "audit": [{"ts": 1_770_000_000, "event": "login", "username": "demoadmin", "ip": "203.0.113.7", "detail": ""}],
    "resources": [{"name": "gaeste", "kind": "pin", "label": "Gäste-Bereich"}],
}

#: Pfade, die das Panel abfragt → JSON. `version` kommt aus der laufenden Bibliothek.
def mock_api(version: str) -> dict[str, object]:
    return {**MOCK, "version": {"version": version}}


# ---------------------------------------------------------------- Vorschau sperren
# Die Panels sind echte Seiten. Sichtbar ja, bedienbar nein: `pointer-events:none` im Kind,
# darüber eine Glasscheibe im Elternteil. Beides zusammen, damit kein Klick durchkommt.
LOCK = ("<style>html{pointer-events:none;user-select:none}"
        "html,body{min-height:0!important}.tsmain{padding:0}"
        "::-webkit-scrollbar{display:none}</style>")
LOCK_CARD = LOCK + "<style>.tsmain{justify-content:flex-start!important;padding:26px 0}</style>"


def readonly(html: str, lock: str = LOCK) -> str:
    return html.replace("</body>", lock + "</body>", 1)


# ---------------------------------------------------------------- Config
BRAND_EXTRA = """
body{font-family:var(--ts-font)}
h1{font-family:var(--ts-serif);font-weight:600}
.card{box-shadow:0 14px 44px rgba(90,60,70,.10)}
input:focus{outline:2px solid var(--ts-accent);border-color:var(--ts-accent)}
button:hover,.btn2:hover{filter:brightness(1.05)}
"""


def brand_css(theme: str) -> str:
    return theme + UI_CSS + BRAND_EXTRA


def demo_config(*, db_path: str, brand: str, icon: str, lang: str = "en", **over):
    """Die Config der Demo — Live-App und statischer Bauschritt teilen sie sich.

    `local_accounts`: nur Benutzername + Passwort, keine E-Mail. Die PIN gibt es, aber nicht
    als Login-Methode, sondern als Bestätigung für sensible Bereiche.
    """
    from tinysesam import TinySesamConfig

    opts = dict(
        db_path=db_path, rp_name="TinySesam", lang=lang, brand_css=brand, brand_icon=icon,
        passkey_enabled=False,
        pin_enabled=True,
        pin_login=False,
        stepup_methods=["totp", "pin"],
        allow_signup=True,
        resource_locks_enabled=True,
        available_roles=["editor", "viewer"],
        cookie_secure=False,
    )
    opts.update(over)
    return TinySesamConfig.local_accounts(**opts)


# ---------------------------------------------------------------- Panels rendern
def render_previews(auth, api_base: str) -> dict[str, str]:
    """Die drei Vorschauen als fertiges HTML. Kein Request, keine Sitzung, keine Schreibzugriffe."""
    from tinysesam.admin import render_panel

    demo_user = {"id": 0, "username": "demo", "display_name": "", "is_admin": 0}
    return {
        # Der Demo-Hinweis mit den Zugangsdaten gehört auf die echte Login-Seite, nicht ins Schaufenster.
        "login": readonly(auth.render_page("login", next="/demo", csrf="", demo_hint=False).body.decode(),
                          LOCK_CARD),
        # `static=True`: die Vorschau lädt nichts nach — sonst fetch't sie ins 401 und wirft JS-Fehler.
        "account": readonly(auth.render_page("account", user=demo_user, methods=auth.cfg.enabled_methods(),
                                             has_totp=True, has_pin=True, is_admin=False, static=True,
                                             admin_path=auth.cfg.admin_path, csrf="").body.decode()),
        "admin": readonly(render_panel(auth, api_base)),
    }


# ---------------------------------------------------------------- Texte + Rahmen
PANEL_T = {
    "en": {
        "demo_h1": "Live demo",
        "demo_hello": "Signed in as <b>{u}</b> — the example pages above are open now.",
        "demo_lead": "Everything TinySesam brings, in one front end. The panels below are "
                     "<b>real pages</b>, rendered live — only the interaction is locked.",
        "demo_lead_static": "Everything TinySesam brings, in one front end. The panels below are "
                            "<b>real pages</b>, rendered at build time from the library itself — "
                            "only the interaction is locked.",
        "p_login": ("Login panel", "The sign-in page shows <b>exactly the methods the config enables</b>. "
                    "Here: username and password. Demo mode reveals the credentials — and warns that "
                    "it must be off in production."),
        "p_account": ("Account panel", "Self-service at <code>/auth/account</code>: password, PIN, "
                      "2FA + recovery codes, passkeys, API keys and your own sessions."),
        "p_admin": ("Admin panel", "Users &amp; roles, sessions, hardening thresholds, audit log. "
                    "Or just the JSON API, for your own panel."),
        "open": "Open →", "ro": "read-only", "ro_fake": "read-only · sample data",
    },
    "de": {
        "demo_h1": "Live-Demo",
        "demo_hello": "Angemeldet als <b>{u}</b> — die Beispielseiten oben sind jetzt begehbar.",
        "demo_lead": "Alles, was TinySesam mitbringt, in einem Frontend. Die Panels unten sind "
                     "<b>echte Seiten</b>, live gerendert — nur die Bedienung ist gesperrt.",
        "demo_lead_static": "Alles, was TinySesam mitbringt, in einem Frontend. Die Panels unten sind "
                            "<b>echte Seiten</b>, zur Bauzeit aus der Bibliothek selbst gerendert — "
                            "nur die Bedienung ist gesperrt.",
        "p_login": ("Login-Panel", "Die Anmeldeseite zeigt <b>genau die Methoden, die die Config "
                    "aktiviert</b>. Hier: Benutzername und Passwort. Der Demo-Modus blendet die "
                    "Zugangsdaten ein — und warnt, dass er produktiv aus gehört."),
        "p_account": ("Konto-Panel", "Selbstverwaltung unter <code>/auth/account</code>: Passwort, PIN, "
                      "2FA + Recovery-Codes, Passkeys, API-Keys und die eigenen Sitzungen."),
        "p_admin": ("Admin-Panel", "Benutzer &amp; Rollen, Sitzungen, Härtungs-Schwellen, "
                    "Audit-Log. Wahlweise nur als JSON-API für dein eigenes Panel."),
        "open": "Öffnen →", "ro": "read-only", "ro_fake": "read-only · Beispieldaten",
    },
}

DEMO_CSS = """
hr.rule{height:1px;background:var(--line);border:0;margin:80px 0}
.shot{margin:0 0 96px}
.shot .head{display:flex;align-items:baseline;justify-content:space-between;gap:14px;
  flex-wrap:wrap;margin-bottom:12px}
.shot .head p{margin:4px 0 0;color:var(--muted);font-size:15px;max-width:60ch}
.frame{position:relative;overflow:hidden;border:1px solid var(--line);border-radius:14px;
  background:var(--card);box-shadow:0 12px 36px rgba(90,60,70,.09);transition:height .2s}
.frame iframe{display:block;border:0;transform-origin:top left}
.frame .glass{position:absolute;inset:0;cursor:default}
.frame .tag{position:absolute;right:10px;top:10px;background:var(--chip);border:1px solid var(--line);
  border-radius:999px;padding:3px 10px;font-size:12px;color:var(--muted)}
"""

# Der Rahmen wächst auf die echte Inhaltshöhe. Das Admin-Panel lädt seine Tabelle per fetch NACH
# dem load-Event — einmaliges Messen schneidet sie ab. Daher ResizeObserver + Nachzügler-Timer.
FIT_JS = """<script>
function tsFit(frame){
  const f = frame.querySelector('iframe'), s = parseFloat(frame.dataset.scale) || 1;
  try{
    const d = f.contentDocument;
    if(!d || !d.body) return;
    const h = Math.max(d.body.scrollHeight, d.body.offsetHeight);
    if(Math.abs(h - (frame._h || 0)) < 2) return;
    frame._h = h;
    f.style.height = h + 'px';
    frame.style.height = Math.ceil(h * s) + 'px';
  }catch(e){}
}
document.querySelectorAll('.frame').forEach(fr => {
  const f = fr.querySelector('iframe');
  f.addEventListener('load', () => {
    tsFit(fr);
    try{ new ResizeObserver(() => tsFit(fr)).observe(f.contentDocument.body); }catch(e){}
    [120, 400, 1000].forEach(ms => setTimeout(() => tsFit(fr), ms));
  });
});
addEventListener('resize', () => document.querySelectorAll('.frame').forEach(fr => { fr._h = 0; tsFit(fr); }));
</script>"""


def shot(title, blurb, src, open_url, height, scale, tag, open_label) -> str:
    # `open_url=None` in der statischen Fassung: dort gibt es keine laufende App, die man
    # öffnen könnte. Ein Knopf, der ins Leere führt, ist schlimmer als keiner.
    btn = f"<a class='btn ghost s' href='{open_url}'>{open_label}</a>" if open_url else ""
    return (f"<section class=shot><div class=head><div><h2>{title}</h2><p>{blurb}</p></div>"
            f"{btn}</div>"
            f"<div class=frame data-scale='{scale}' style='height:{height}px'>"
            f"<iframe src='{src}' tabindex=-1 scrolling=no title='{escape(title)}'"
            f" style='width:{100 / scale:.0f}%;height:{height / scale:.0f}px;transform:scale({scale})'></iframe>"
            f"<span class=glass></span><span class=tag>{tag}</span></div></section>")


#: (Schlüssel, Höhe, Maßstab) — die Maße sind in beiden Ausgaben gleich.
PANELS = (("login", 470, 0.86), ("account", 470, 0.8), ("admin", 520, 0.66))


def demo_body(lang: str, *, src: dict, open_urls: dict | None = None, lead: str | None = None) -> str:
    """Der Inhalt der Demo-Seite (ohne Rumpf). `src` je Panel-Schlüssel.

    Ohne `open_urls` (statische Fassung) entfallen die „Öffnen"-Knöpfe.
    """
    t = PANEL_T[lang]
    lead = lead or t["demo_lead_static"]
    panels = "".join(
        shot(*t[f"p_{k}"], src[k], (open_urls or {}).get(k), h, s,
             t["ro_fake"] if k == "admin" else t["ro"], t["open"])
        for k, h, s in PANELS)
    return f"<h1>{t['demo_h1']}</h1><p class=lead>{lead}</p><hr class=rule>{panels}{FIT_JS}"


#: Das Admin-Panel ist **nicht übersetzt** — `tinysesam/admin.py` trägt sein Deutsch fest im
#: Template (`<html lang=de>`, Reiter „Benutzer/Sitzungen/Härtung/Audit"). Zwei Sprachfassungen
#: wären Byte für Byte gleich, also wird es einmal gebaut. Sobald das Panel `auth.t()` benutzt,
#: gehört es hier in `PER_LANG`. Siehe TODO.md.
PER_LANG = ("login", "account")


def static_src(lang: str) -> dict[str, str]:
    """Die Frame-Quellen der gebauten Seite — relativ zu `demo.html` im Wurzelverzeichnis."""
    return {k: (f"demo/{k}.{lang}.html" if k in PER_LANG else f"demo/{k}.html")
            for k, _h, _s in PANELS}


# ---------------------------------------------------------------- Statischer Bauschritt
def build(out: Path, theme: str, icon: str) -> list[str]:
    """Schreibt `demo/<panel>.<lang>.html` und die Attrappen-API. Gibt die Dateinamen zurück.

    Für jede Sprache eine eigene Fassung: die Panels kommen aus der Bibliothek und sprechen
    deren `lang`. Die Seite blendet dann per `l-en`/`l-de` den passenden Rahmen ein — dasselbe
    Sprachsystem wie überall, keine Sprach-Dateinamen in der URL.
    """
    from tinysesam import TinySesam, __version__

    demo_dir = out / "demo"
    api_dir = demo_dir / "adminapi" / "api"
    api_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    # Das Panel ruft `<base>/api/<name>`. Die Seite liegt in `demo/`, also ist `adminapi`
    # der richtige relative Bezug. Dateien ohne Endung: `fetch(...).json()` prüft keinen
    # Content-Type, und Pages liefert sie unverändert aus.
    for name, payload in mock_api(__version__).items():
        (api_dir / name).write_text(json.dumps(payload), encoding="utf-8")
        written.append(f"demo/adminapi/api/{name}")

    for lang in LANGS:
        # `admin_claim_ttl_min=0`: sonst erzeugt jeder Bau ein Erst-Admin-Token und schreibt es
        # ins Log. Für ein Schaufenster ohne Konten ist das sinnlos und nur verwirrend.
        auth = TinySesam(demo_config(db_path=":memory:", brand=brand_css(theme), icon=icon,
                                     lang=lang, admin_claim_ttl_min=0))
        for key, html in render_previews(auth, "adminapi").items():
            if key not in PER_LANG:
                if lang != LANGS[0]:
                    continue
                name = f"demo/{key}.html"
            else:
                name = f"demo/{key}.{lang}.html"
            (out / name).write_text(html, encoding="utf-8")
            written.append(name)
    return written

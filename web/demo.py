"""The demo page — in one place, for two outputs.

* `examples/showcase.py` renders it **live** under `/demo` and serves the previews
  from routes of its own.
* `web.build` bakes it **statically** into `demo.html` + `demo/*.html` for GitHub Pages,
  where no server process runs.

Both use the same config (`demo_config`), the same example data (`MOCK`) and
the same frame (`shot`, `DEMO_CSS`, `FIT_JS`) — otherwise showcase and website drift
apart, and that has happened before.

`tinysesam` is **imported only inside the functions** that need it (`demo_config`,
`render_previews`, `build`). Texts, CSS and the page shell thereby stay importable
without FastAPI installed — `site.py` still builds the website from the plain
standard library.

The static panels are created against an **in-memory database** (`db_path=":memory:"`):
no temporary file, nothing to clean up. Only the hard-coded example data below is
shown — nothing is seeded.
"""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from .ui import LANGS, UI_CSS

# ---------------------------------------------------------------- Example data
# What the admin panel shows in the preview. It fetches it via `fetch` from `<base>/api/…`;
# live, a read-only dummy route answers, statically they sit next to it as files.
# IP per RFC 5737 (documentation range) — the hygiene test forbids real addresses.
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
    "resources": [{"name": "gaeste", "kind": "pin", "label": "Guest area"}],
}

#: Paths the panel queries → JSON. `version` comes from the running library.
def mock_api(version: str) -> dict[str, object]:
    return {**MOCK, "version": {"version": version}}


# ---------------------------------------------------------------- Locking the preview
# The panels are real pages. Visible yes, operable no: `pointer-events:none` in the child,
# a glass pane above it in the parent. Both together so that no click gets through.
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
    """The demo config — live app and static build step share it.

    `local_accounts`: only username + password, no email. The PIN exists, but not
    as a login method, rather as confirmation for sensitive areas.
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


# ---------------------------------------------------------------- Rendering the panels
def render_previews(auth, api_base: str) -> dict[str, str]:
    """The three previews as finished HTML. No request, no session, no write access."""
    from tinysesam.admin import render_panel

    demo_user = {"id": 0, "username": "demo", "display_name": "", "is_admin": 0}
    return {
        # The demo notice with the credentials belongs on the real login page, not in the showcase.
        "login": readonly(auth.render_page("login", next="/demo", csrf="", demo_hint=False).body.decode(),
                          LOCK_CARD),
        # `static=True`: the preview loads nothing afterwards — otherwise it fetches into a 401 and throws JS errors.
        "account": readonly(auth.render_page("account", user=demo_user, methods=auth.cfg.enabled_methods(),
                                             has_totp=True, has_pin=True, is_admin=False, static=True,
                                             admin_path=auth.cfg.admin_path, csrf="").body.decode()),
        "admin": readonly(render_panel(auth, api_base)),
    }


# ---------------------------------------------------------------- Texts + frame
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
        "p_account": ("Account panel", "Self-service at <code>/auth/account</code>: password, "
                      "2FA + recovery codes, API keys and your own sessions. The page follows the "
                      "config — this demo runs without PIN and without passkeys, so those two "
                      "sections are absent here."),
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
        "p_account": ("Konto-Panel", "Selbstverwaltung unter <code>/auth/account</code>: Passwort, "
                      "2FA + Recovery-Codes, API-Keys und die eigenen Sitzungen. Die Seite folgt der "
                      "Config — diese Demo läuft ohne PIN und ohne Passkeys, deshalb fehlen die "
                      "beiden Abschnitte hier."),
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

# The frame grows to the real content height. The admin panel loads its table via fetch AFTER
# the load event — measuring once cuts it off. Hence ResizeObserver + straggler timer.
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
    # `open_url=None` in the static version: there is no running app there that could be
    # opened. A button that leads nowhere is worse than none.
    btn = f"<a class='btn ghost s' href='{open_url}'>{open_label}</a>" if open_url else ""
    return (f"<section class=shot><div class=head><div><h2>{title}</h2><p>{blurb}</p></div>"
            f"{btn}</div>"
            f"<div class=frame data-scale='{scale}' style='height:{height}px'>"
            f"<iframe src='{src}' tabindex=-1 scrolling=no title='{escape(title)}'"
            f" style='width:{100 / scale:.0f}%;height:{height / scale:.0f}px;transform:scale({scale})'></iframe>"
            f"<span class=glass></span><span class=tag>{tag}</span></div></section>")


#: (key, height, scale) — the dimensions are the same in both outputs.
PANELS = (("login", 470, 0.86), ("account", 470, 0.8), ("admin", 520, 0.66))


def demo_body(lang: str, *, src: dict, open_urls: dict | None = None, lead: str | None = None) -> str:
    """The content of the demo page (without shell). `src` per panel key.

    Without `open_urls` (static version) the "Open" buttons are omitted.
    """
    t = PANEL_T[lang]
    lead = lead or t["demo_lead_static"]
    panels = "".join(
        shot(*t[f"p_{k}"], src[k], (open_urls or {}).get(k), h, s,
             t["ro_fake"] if k == "admin" else t["ro"], t["open"])
        for k, h, s in PANELS)
    return f"<h1>{t['demo_h1']}</h1><p class=lead>{lead}</p><hr class=rule>{panels}{FIT_JS}"


#: All panels speak `cfg.lang`, so each gets one file per language. (Until 0.13.1 the
#: admin panel carried its German hard-wired in the template and was therefore built only once.)
PER_LANG = ("login", "account", "admin")


def static_src(lang: str) -> dict[str, str]:
    """The frame sources of the built page — relative to `demo.html` in the root directory."""
    return {k: (f"demo/{k}.{lang}.html" if k in PER_LANG else f"demo/{k}.html")
            for k, _h, _s in PANELS}


# ---------------------------------------------------------------- Static build step
def build(out: Path, theme: str, icon: str) -> list[str]:
    """Writes `demo/<panel>.<lang>.html` and the dummy API. Returns the file names.

    One version per language: the panels come from the library and speak
    its `lang`. The page then shows the matching frame via `l-en`/`l-de` — the same
    language system as everywhere, no language file names in the URL.
    """
    from tinysesam import TinySesam, __version__

    demo_dir = out / "demo"
    api_dir = demo_dir / "adminapi" / "api"
    api_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    # The panel calls `<base>/api/<name>`. The page lives in `demo/`, so `adminapi`
    # is the right relative reference. Files without extension: `fetch(...).json()` checks no
    # Content-Type, and Pages serves them unchanged.
    for name, payload in mock_api(__version__).items():
        (api_dir / name).write_text(json.dumps(payload), encoding="utf-8")
        written.append(f"demo/adminapi/api/{name}")

    for lang in LANGS:
        # `admin_claim_ttl_min=0`: otherwise every build creates a first-admin token and writes it
        # into the log. For a showcase without accounts that is pointless and only confusing.
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

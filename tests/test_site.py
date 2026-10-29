"""The project website: one source, two languages — and the body from web/ui.py."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _lies(*parts: str) -> str:
    return Path(*parts).read_text(encoding="utf-8")


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tinysesam import __version__ as TS_VERSION  # noqa: E402

# Before the first web import: the website generator exists only in the repo, not in the sdist.
# A precondition that comes AFTER the import is too late — the
# ModuleNotFoundError has already been thrown.
import pathlib  # noqa: E402
from voraussetzung import braucht  # noqa: E402

braucht((pathlib.Path(__file__).resolve().parent.parent / "web").is_dir(),
        "no `web/` — the website generator lives only in the repo, not in the sdist")

from web.flows import FLOWS, render                       # noqa: E402
from web.site import DEMO, FLOWS as FLOWS_FILE, INDEX, LEGAL, OWNER, LABELS, build_pages  # noqa: E402
from web.ui import LANG_COOKIE, LANGS, Ctx, Nav, footer, header  # noqa: E402


# ---------- Flow data ----------
for f in FLOWS:
    assert f["key"] and f["config"] and callable(f["active"]), f
    for lang in LANGS:
        loc = f[lang]
        assert loc["title"] and loc["why"] and loc["steps"], (f["key"], lang)
        for kind, _text in loc["steps"]:
            assert kind in ("do", "srv", "end"), (f["key"], lang, kind)
print(f"  {len(FLOWS)} flows, both languages, box types ok")

# ---------- render(): static = config switch, with cfg = active/off ----------
static = render("en", cfg=None)
assert "pill cfg" in static and "pill on" not in static and "pill off" not in static
assert static.count("<section class=flow>") == len(FLOWS)


class _Cfg:
    """A config dummy: what this check needs is set — everything else comes from the
    defaults of `TinySesamConfig`.

    The fallback via `__getattr__` is the actual point. Before, the dummy listed its
    fields one by one and broke as soon as a flow read another field (most recently `ldap_enabled`).
    That turned an extension of the page into a failure in a completely different file — and
    tempts one to add the field there instead of using it in `flows.py`.
    """

    login_identifier = "username"
    pin_login = False
    stepup_methods = ["pin"]
    stepup_max_age_sec = 900
    totp_enabled = True
    resource_locks_enabled = True
    magiclink_enabled = False
    oidc_enabled = False
    saml_enabled = False
    forward_auth_enabled = False

    def enabled_methods(self):
        return ["password"]

    def __getattr__(self, name):
        from tinysesam import TinySesamConfig
        default = TinySesamConfig(db_path=":memory:")
        if not hasattr(default, name):
            raise AttributeError(f"neither in the stub nor in TinySesamConfig: {name}")
        return getattr(default, name)


live = render("de", cfg=_Cfg())
assert "pill cfg" not in live
assert live.count("pill on") == 5 and live.count("pill off") == 4
assert "Benutzername</b>" in live, "note(cfg) is evaluated"
print("  render(): static = config switch, with cfg = active/off")

# ---------- Four files, each bilingual — ONE language system ----------
pages = build_pages()
assert set(pages) == {INDEX, DEMO, FLOWS_FILE, LEGAL}, sorted(pages)
assert not any(".de.html" in k for k in pages), "no language file names"

for name, marks in ((INDEX, ("Use only what you need", "Nutze nur, was du brauchst")),
                    (DEMO, ("Live demo", "Live-Demo")),
                    (FLOWS_FILE, ("Sign-in flows", "Login-Flows")),
                    (LEGAL, ("Legal notice", "Impressum & Datenschutz"))):
    html = pages[name]
    for m in marks:
        assert m in html, (name, m)
    # both language versions are in the file, one is hidden
    assert '<div class="l-en">' in html and '<div class="l-de">' in html
    assert 'html[data-lang="en"] .l-de{display:none}' in html
    # the switcher uses the same parameter everywhere
    for code in LANGS:
        assert f"href='?lang={code}'" in html, (name, code)
    # No language file names for PAGES. The panel previews of the demo are not pages
    # but iframe contents — they are called `demo/login.de.html`, and that is intentional.
    for page_name in ("index", "flows", "legal"):
        assert f"{page_name}.de" not in html, (name, page_name)
    # and the same cookie as the app
    assert LANG_COOKIE in html
    # The default is English: `?lang=` > cookie > LANGS[0]. The browser language does NOT count —
    # otherwise a German browser would see the German version unasked.
    assert "navigator.language" not in html, "browser language must not override the default"
    assert "cookie('ts_lang') || LANGS[0]" in html
    assert 'href="theme.css"' in html and 'href="wizard.png"' in html
    assert "flaticon.com/free-icons/wizard" in html, "Icon-Attribution"
print("  2 files, both languages, one `?lang=` parameter + one cookie")

# ---------- The body: one header container, two nav rows, same footer ----------
def _cut(h, a, b):
    i = h.index(a)
    return h[i:h.index(b, i) + len(b)]


for name in (INDEX, FLOWS_FILE, LEGAL):
    h = pages[name]
    assert h.count("<header class=shell>") == 2, "one header per language version"
    assert h.count("<nav class='row pages'>") == 2 and h.count("<nav class='row tools'>") == 2
    assert h.count("<footer") == 2
    assert "id=ts-theme" in h and "data-theme=light" in h and "data-theme=dark" in h
    assert "details.dd[open]" in h and "e.key==='Escape'" in h

# ---------- Legal notice + privacy ----------
legal = pages[LEGAL]
for probe in ("§ 5 DDG", "Art. 6 Abs. 1 lit. f DSGVO", "GitHub, Inc.", "EU-US Data Privacy Framework",
              "ts_lang", "ts-theme", "Art. 15", "Cookie-Banner"):
    assert probe in legal, probe
# Placeholders stand out in red — but are now filled in
for key in ("name", "street", "city", "email"):
    assert OWNER[key] and not OWNER[key].startswith("«"), f"OWNER[{key}] missing"
    assert OWNER[key] in legal, key
assert "class=todo" not in legal, "no unfilled details any more"
# The scope must make clear: only this one address, not self-hosted copies
assert "ollornog.github.io/TinySesam" in legal
for probe in ("eigenen Server installiert", "on their own server"):
    assert probe in legal, probe
assert all(f'href="{LEGAL}"' in pages[p] for p in (INDEX, FLOWS_FILE, LEGAL)), "footer linked"
print("  legal.html: Impressum (§5 DDG), Hosting, Browser-Speicher, Betroffenenrechte")

idx, fl = pages[INDEX], pages[FLOWS_FILE]
assert "class=hero" in _cut(idx, "<header class=shell>", "</header>")
assert "class=brand" not in _cut(idx, "<header class=shell>", "</header>")
assert "class=brand" in _cut(fl, "<header class=shell>", "</header>")
print("  header: one container + two nav rows; start page with title area instead of brand")

# ---------- ui building blocks ----------
_nav = Nav(brand_href="/", icon_url="w.png", repo="https://example.invalid",
           pages=(("/a", "A"), ("/b", "B")), auth=True)
_ctx = Ctx(lang="de", labels=LABELS["de"], lang_hrefs={"en": "?l=en", "de": "?l=de"}, path="/a")
h = header(_ctx, _nav)
assert "class='on' href='/a'" in h and "class='' href='/b'" in h
assert "Anmelden" in h and "Registrieren" in h, "signed out: sign-in/register"
_ctx.user = {"username": "max"}
_ctx.is_admin = True
h = header(_ctx, _nav)
assert "max" in h and "Admin-Panel" in h and "Abmelden" in h and "Anmelden" not in h
assert footer(_ctx, _nav).count("<footer") == 1
print("  ui.header/ui.footer: pages marked, profile menu only with user")

# ---------- Icon links must not be squeezed by the page-link padding ----------
from web.ui import UI_CSS  # noqa: E402

assert "nav.row a:not(.ilink){padding:6px 11px}" in UI_CSS, (
    "otherwise `nav.row a` (0,1,2) beats the `.ilink` padding (0,1,0) and the icon becomes 4px wide")
assert ".ilink svg{width:20px;height:20px;flex:0 0 auto" in UI_CSS, "icon must not shrink"
assert "height:22px" in UI_CSS.split(".ilink{")[1].split("}")[0], "icon frame = pill height"
print("  .ilink: own padding, icon 20px, no flex shrinking")

# ---------- One language system: nowhere a file name, everywhere `?lang=` ----------
for name in (INDEX, FLOWS_FILE, LEGAL):
    html = pages[name]
    i = html.index("<span class=pill2>")
    pill = html[i:html.index("</span>", i)]
    for code in LANGS:
        assert f"href='?lang={code}'" in pill, (name, code)
print("  language switcher: `?lang=` everywhere, no language file names")

# ---------- The generator that the GitHub action calls ----------
with tempfile.TemporaryDirectory() as tmp:
    subprocess.run([sys.executable, "-m", "web.build", tmp], cwd=ROOT, check=True, capture_output=True)
    have = sorted(os.listdir(tmp))
    assert have == sorted([".nojekyll", "demo", "demo.html", "flows.html", "index.html",
                           "legal.html", "theme.css", "wizard.png"]), have

    # The previews of the demo page: each panel per language — all three speak `cfg.lang`.
    # Plus the dummy API as files.
    demo = sorted(os.listdir(os.path.join(tmp, "demo")))
    assert demo == sorted(["adminapi",
                           "login.en.html", "login.de.html",
                           "account.en.html", "account.de.html",
                           "admin.en.html", "admin.de.html"]), demo

    api = os.path.join(tmp, "demo", "adminapi", "api")
    assert sorted(os.listdir(api)) == sorted(["users", "sessions", "security", "audit",
                                              "resources", "version"])
    # Without extension, but JSON: `fetch(...).json()` checks no Content-Type, and Pages
    # serves the file unchanged.
    users = json.loads(_lies(api, "users"))
    assert [u["username"] for u in users] == ["demoadmin", "demo", "martin", "backup-daemon"]
    version = json.loads(_lies(api, "version"))
    assert version["version"] == TS_VERSION, "the panel shows the built version"

    # The panels are real pages, but locked — and the demo page embeds exactly them.
    def panel(name):
        return _lies(tmp, "demo", name)

    for name in ("admin.en.html", "admin.de.html", "login.en.html", "account.de.html"):
        assert "pointer-events:none" in panel(name), f"{name} must be read-only"
    assert "<form" in panel("login.en.html")

    # Every panel speaks the language of its file — the admin panel too.
    for name, lang, want, nope in (("admin.en.html", "en", "Hardening", "Härtung"),
                                   ("admin.de.html", "de", "Härtung", "Hardening"),
                                   ("login.en.html", "en", "Sign in", "Anmelden"),
                                   ("login.de.html", "de", "Anmelden", "Sign in")):
        html = panel(name)
        assert f"lang={lang}" in html or f'lang="{lang}"' in html, name
        assert want in html and nope not in html, (name, want, nope)

    page = _lies(tmp, "demo.html")
    for src in ("demo/login.en.html", "demo/account.de.html", "demo/admin.en.html",
                "demo/admin.de.html"):
        assert f"src='{src}'" in page, src
    # Nothing runs on Pages — an “Open” button would have no target.
    assert "/auth/login" not in page, "the built page links no running app"
print("  web.build schreibt Seiten, Demo-Panels, Attrappen-API + .nojekyll")

# ---------- Showcase: the username is text (R8-2) ----------
# T-12 escaped it on /app and /sensitive; /demo (“Signed in as …”) stayed raw. An account named
# <img src=x onerror=…> thereby ran as code on every own visit to the demo page.
os.environ["TINYSESAM_SHOWCASE_DB"] = os.path.join(tempfile.mkdtemp(), "showcase.db")
from fastapi.testclient import TestClient  # noqa: E402
import examples.showcase as showcase  # noqa: E402

_evil = "<img src=x onerror=alert(1)>"
showcase.auth.create_user(_evil, password="geheim-passwort-1")
_c = TestClient(showcase.app)
_c.get("/auth/login")
_r = _c.post("/auth/login", data={"username": _evil, "password": "geheim-passwort-1", "next": "/",
                                  "_csrf": _c.cookies.get(showcase.auth.cfg.csrf_cookie)},
             follow_redirects=False)
assert _r.status_code == 303, _r.status_code
for _away in ("/demo", "/app"):
    _t = _c.get(_away).text
    assert "<img src=x" not in _t and "&lt;img src=x onerror=alert(1)&gt;" in _t, _away
print("  showcase: a crafted username stays text on /demo and /app")

print("OK test_site")

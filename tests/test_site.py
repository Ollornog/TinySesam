"""Die Projekt-Website: eine Quelle, zwei Sprachen — und der Rumpf aus web/ui.py."""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from web.flows import FLOWS, render                       # noqa: E402
from web.site import LABELS, build_pages, page_url        # noqa: E402
from web.ui import LANGS, Ctx, Nav, header, footer        # noqa: E402

# ---------- Flow-Daten ----------
for f in FLOWS:
    assert f["key"] and f["config"] and callable(f["active"]), f
    for lang in LANGS:
        loc = f[lang]
        assert loc["title"] and loc["why"] and loc["steps"], (f["key"], lang)
        for kind, _text in loc["steps"]:
            assert kind in ("do", "srv", "end"), (f["key"], lang, kind)
print(f"  {len(FLOWS)} Flows, beide Sprachen, Kästchen-Typen ok")

# ---------- render(): statisch = Config-Schalter, mit cfg = aktiv/aus ----------
static = render("en", cfg=None)
assert "pill cfg" in static and "pill on" not in static and "pill off" not in static
assert static.count("<section class=flow>") == len(FLOWS)


class _Cfg:
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


live = render("de", cfg=_Cfg())
assert "pill cfg" not in live
assert live.count("pill on") == 5 and live.count("pill off") == 4
assert "Benutzername</b>" in live, "note(cfg) wird ausgewertet"
print("  render(): statisch = Config-Schalter, mit cfg = aktiv/aus")

# ---------- Vier Seiten, je Sprache, mit Sprach-Pille ----------
pages = build_pages()
assert set(pages) == {"index.html", "index.de.html", "flows.html", "flows.de.html"}, sorted(pages)
assert 'lang="en"' in pages["index.html"] and 'lang="de"' in pages["index.de.html"]
assert "Use only what you need" in pages["index.html"]
assert "Nutze nur, was du brauchst" in pages["index.de.html"]
assert "Sign-in flows" in pages["flows.html"] and "Login-Flows" in pages["flows.de.html"]

for page in ("index", "flows"):
    for lang in LANGS:
        html = pages[page_url(page, lang)]
        for code in LANGS:
            assert f"href='{page_url(page, code)}'>{code.upper()}<" in html, (page, lang, code)
        assert f"'seg on' href='{page_url(page, lang)}'" in html, "aktives Segment"
        assert 'href="theme.css"' in html and 'href="wizard.png"' in html
        assert "flaticon.com/free-icons/wizard" in html, "Icon-Attribution"
print("  4 Seiten, Sprach-Pille, Assets + Attribution ok")

# ---------- Der Rumpf: ein Kopf-Container, zwei Navreihen, gleiche Fußzeile ----------
def _cut(h, a, b):
    i = h.index(a)
    return h[i:h.index(b, i) + len(b)]


feet = set()
for page in ("index", "flows"):
    for lang in LANGS:
        h = pages[page_url(page, lang)]
        assert h.count("<header class=shell>") == 1
        assert h.count("<nav class='row pages'>") == 1 and h.count("<nav class='row tools'>") == 1
        assert "id=ts-theme" in h and "data-theme=light" in h and "data-theme=dark" in h
        assert "details.dd[open]" in h and "e.key==='Escape'" in h
        feet.add(_cut(h, "<footer", "</footer>"))
    # Startseite: Titelbereich statt Marke
    idx = pages[page_url("index", lang)]
    head = _cut(idx, "<header class=shell>", "</header>")
    assert "class=hero" in head and "class=brand" not in head
    assert "class=brand" in _cut(pages[page_url("flows", lang)], "<header class=shell>", "</header>")

assert len(feet) == 2, "je Sprache eine Fußzeile, sonst identisch"
print("  Kopf: ein Container + zwei Navreihen; Fußzeile je Sprache identisch")

# ---------- ui-Bausteine ----------
_nav = Nav(brand_href="/", icon_url="w.png", repo="https://example.invalid",
           pages=(("/a", "A"), ("/b", "B")), auth=True)
_ctx = Ctx(lang="de", labels=LABELS["de"], lang_hrefs={"en": "?l=en", "de": "?l=de"}, path="/a")
h = header(_ctx, _nav)
assert "class='on' href='/a'" in h and "class='' href='/b'" in h
assert "Anmelden" in h and "Registrieren" in h, "ausgeloggt: An-/Registrieren"
_ctx.user = {"username": "max"}
_ctx.is_admin = True
h = header(_ctx, _nav)
assert "max" in h and "Admin-Panel" in h and "Abmelden" in h and "Anmelden" not in h
assert footer(_ctx, _nav).count("<footer") == 1
print("  ui.header/ui.footer: Seiten markiert, Profil-Menü nur mit Benutzer")

# ---------- Icon-Links dürfen nicht vom Seitenlink-Polster gequetscht werden ----------
from web.ui import UI_CSS  # noqa: E402

assert "nav.row a:not(.ilink){padding:6px 11px}" in UI_CSS, (
    "sonst schlägt `nav.row a` (0,1,2) das `.ilink`-Padding (0,1,0) und das Icon wird 4px breit")
assert ".ilink svg{width:20px;height:20px;flex:0 0 auto" in UI_CSS, "Icon darf nicht schrumpfen"
assert "height:22px" in UI_CSS.split(".ilink{")[1].split("}")[0], "Icon-Rahmen = Pillenhöhe"
print("  .ilink: eigenes Polster, Icon 20px, kein Flex-Schrumpfen")

# ---------- Der Sprachwechsler muss auf die andere Fassung DERSELBEN Seite zeigen ----------
# Seiten mit der Sprache im Dateinamen dürfen kein `?lang=` benutzen: die Datei gewinnt.
for page in ("index", "flows"):
    for lang in LANGS:
        html = pages[page_url(page, lang)]
        i = html.index("<span class=pill2>")
        pill = html[i:html.index("</span>", i)]
        assert "?lang=" not in pill, (page, lang, "Dateiname schlägt den Query-Parameter")
        for code in LANGS:
            assert f"href='{page_url(page, code)}'" in pill, (page, lang, code)
print("  Sprachwechsler: verweist auf die Datei, nicht auf ?lang=")

# ---------- Der Generator, den die GitHub-Action ruft ----------
with tempfile.TemporaryDirectory() as tmp:
    subprocess.run([sys.executable, "-m", "web.build", tmp], cwd=ROOT, check=True, capture_output=True)
    have = sorted(os.listdir(tmp))
    assert have == sorted([".nojekyll", "flows.de.html", "flows.html", "index.de.html",
                           "index.html", "theme.css", "wizard.png"]), have
print("  web.build schreibt Seiten + Assets + .nojekyll")

print("OK test_site")

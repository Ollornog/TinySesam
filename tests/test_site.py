"""Die Projekt-Website: eine Quelle, zwei Sprachen — und der Rumpf aus web/ui.py."""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from web.flows import FLOWS, render                       # noqa: E402
from web.site import FLOWS as FLOWS_FILE, INDEX, LEGAL, OWNER, LABELS, build_pages  # noqa: E402
from web.ui import LANG_COOKIE, LANGS, Ctx, Nav, footer, header  # noqa: E402

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

# ---------- Zwei Dateien, jede zweisprachig — EIN Sprachsystem ----------
pages = build_pages()
assert set(pages) == {INDEX, FLOWS_FILE, LEGAL}, sorted(pages)
assert not any(".de.html" in k for k in pages), "keine Sprach-Dateinamen"

for name, marks in ((INDEX, ("Use only what you need", "Nutze nur, was du brauchst")),
                    (FLOWS_FILE, ("Sign-in flows", "Login-Flows")),
                    (LEGAL, ("Legal notice", "Impressum & Datenschutz"))):
    html = pages[name]
    for m in marks:
        assert m in html, (name, m)
    # beide Sprachfassungen liegen in der Datei, eine wird ausgeblendet
    assert '<div class="l-en">' in html and '<div class="l-de">' in html
    assert 'html[data-lang="en"] .l-de{display:none}' in html
    # der Wechsler benutzt überall denselben Parameter
    for code in LANGS:
        assert f"href='?lang={code}'" in html, (name, code)
    assert ".de.html" not in html and "index.de" not in html
    # und dasselbe Cookie wie die App
    assert LANG_COOKIE in html and "navigator.language" in html
    assert 'href="theme.css"' in html and 'href="wizard.png"' in html
    assert "flaticon.com/free-icons/wizard" in html, "Icon-Attribution"
print("  2 Dateien, beide Sprachen, ein `?lang=`-Parameter + ein Cookie")

# ---------- Der Rumpf: ein Kopf-Container, zwei Navreihen, gleiche Fußzeile ----------
def _cut(h, a, b):
    i = h.index(a)
    return h[i:h.index(b, i) + len(b)]


for name in (INDEX, FLOWS_FILE, LEGAL):
    h = pages[name]
    assert h.count("<header class=shell>") == 2, "je Sprachfassung ein Kopf"
    assert h.count("<nav class='row pages'>") == 2 and h.count("<nav class='row tools'>") == 2
    assert h.count("<footer") == 2
    assert "id=ts-theme" in h and "data-theme=light" in h and "data-theme=dark" in h
    assert "details.dd[open]" in h and "e.key==='Escape'" in h

# ---------- Impressum + Datenschutz ----------
legal = pages[LEGAL]
for probe in ("§ 5 DDG", "Art. 6 Abs. 1 lit. f DSGVO", "GitHub, Inc.", "EU-US Data Privacy Framework",
              "ts_lang", "ts-theme", "Art. 15", "Cookie-Banner"):
    assert probe in legal, probe
# Platzhalter fallen rot auf — sind jetzt aber ausgefüllt
for key in ("name", "street", "city", "email"):
    assert OWNER[key] and not OWNER[key].startswith("«"), f"OWNER[{key}] fehlt"
    assert OWNER[key] in legal, key
assert "class=todo" not in legal, "keine unausgefüllten Angaben mehr"
# Der Geltungsbereich muss klarstellen: nur diese eine Adresse, nicht selbstgehostete Kopien
assert "ollornog.github.io/TinySesam" in legal
for probe in ("eigenen Server installiert", "on their own server"):
    assert probe in legal, probe
assert all(f'href="{LEGAL}"' in pages[p] for p in (INDEX, FLOWS_FILE, LEGAL)), "Fußzeile verlinkt"
print("  legal.html: Impressum (§5 DDG), Hosting, Browser-Speicher, Betroffenenrechte")

idx, fl = pages[INDEX], pages[FLOWS_FILE]
assert "class=hero" in _cut(idx, "<header class=shell>", "</header>")
assert "class=brand" not in _cut(idx, "<header class=shell>", "</header>")
assert "class=brand" in _cut(fl, "<header class=shell>", "</header>")
print("  Kopf: ein Container + zwei Navreihen; Startseite mit Titelbereich statt Marke")

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

# ---------- Ein Sprachsystem: nirgends ein Dateiname, überall `?lang=` ----------
for name in (INDEX, FLOWS_FILE, LEGAL):
    html = pages[name]
    i = html.index("<span class=pill2>")
    pill = html[i:html.index("</span>", i)]
    for code in LANGS:
        assert f"href='?lang={code}'" in pill, (name, code)
print("  Sprachwechsler: überall `?lang=`, keine Sprach-Dateinamen")

# ---------- Der Generator, den die GitHub-Action ruft ----------
with tempfile.TemporaryDirectory() as tmp:
    subprocess.run([sys.executable, "-m", "web.build", tmp], cwd=ROOT, check=True, capture_output=True)
    have = sorted(os.listdir(tmp))
    assert have == sorted([".nojekyll", "flows.html", "index.html", "legal.html",
                           "theme.css", "wizard.png"]), have
print("  web.build schreibt Seiten + Assets + .nojekyll")

print("OK test_site")

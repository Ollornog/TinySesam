"""Die Projekt-Website: eine Quelle, zwei Sprachen — und der Generator, den die Action fährt."""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from web.flows import FLOWS, render          # noqa: E402
from web.site import LANGS, build_pages, page_url  # noqa: E402

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
assert live.count("pill on") == 5 and live.count("pill off") == 4, (live.count("pill on"), live.count("pill off"))
assert "Benutzername</b>" in live, "note(cfg) wird ausgewertet"
print("  render(): statisch = Config-Schalter, mit cfg = aktiv/aus")

# ---------- Vier Seiten, jede in ihrer Sprache, mit Umschalter ----------
pages = build_pages()
assert set(pages) == {"index.html", "index.de.html", "flows.html", "flows.de.html"}, sorted(pages)

assert 'lang="en"' in pages["index.html"] and 'lang="de"' in pages["index.de.html"]
assert "Use only what you need" in pages["index.html"]
assert "Nutze nur, was du brauchst" in pages["index.de.html"]
assert "Sign-in flows" in pages["flows.html"] and "Login-Flows" in pages["flows.de.html"]

# Sprachwechsel als Dropdown, zeigt auf beide Fassungen derselben Seite
for page in ("index", "flows"):
    for lang in LANGS:
        html = pages[page_url(page, lang)]
        for code in LANGS:
            assert f"href='{page_url(page, code)}'" in html, (page, lang, code)
        assert "class='dd r'" in html, "Sprach-Dropdown fehlt"

# Beide Leisten, richtige Reihenfolge: Flow-Seite top→sub, Startseite Titelbereich→sub
for lang in LANGS:
    idx, fl = pages[page_url("index", lang)], pages[page_url("flows", lang)]
    assert "<nav class=top" not in idx, "Startseite: Titelbereich ersetzt die erste Leiste"
    assert idx.find('<header class="hero"') < idx.find("<nav class=sub") > -1
    assert -1 < fl.find("<nav class=top") < fl.find("<nav class=sub"), "erste Leiste muss oben stehen"
print("  Navigation: beide Leisten, Reihenfolge stimmt")

# Nichts Hartkodiertes: beide Sprachen verlinken theme.css/wizard.png relativ
for html in pages.values():
    assert 'href="theme.css"' in html and 'href="wizard.png"' in html
    assert "flaticon.com/free-icons/wizard" in html, "Icon-Attribution fehlt"
print("  4 Seiten, Sprachumschalter, Assets + Attribution ok")

# ---------- Der Generator, den die GitHub-Action ruft ----------
with tempfile.TemporaryDirectory() as tmp:
    subprocess.run([sys.executable, "-m", "web.build", tmp], cwd=ROOT, check=True, capture_output=True)
    have = sorted(os.listdir(tmp))
    assert have == sorted([".nojekyll", "flows.de.html", "flows.html", "index.de.html",
                           "index.html", "theme.css", "wizard.png"]), have
print("  web.build schreibt Seiten + Assets + .nojekyll")



# ---------- Die drei Elemente: nav1, nav2, Fußzeile ----------
from web.site import nav_top  # noqa: E402


def slice_(html, start, end):
    i = html.index(start)
    return html[i:html.index(end, i)]


for lang in LANGS:
    bars1, bars2, feet = [], [], []
    for page in ("index", "flows"):
        html = pages[page_url(page, lang)]
        bars1.append(slice_(html, "<nav class", "</nav>"))
        bars2.append(slice_(html, "<nav class=sub", "</nav>"))
        feet.append(slice_(html, "<footer", "</footer>"))

    # Fußzeile: auf jeder Seite exakt gleich
    assert feet[0] == feet[1], f"Fußzeile weicht ab ({lang})"

    # nav1 trägt die Werkzeuge: Sprache (Kürzel in der Leiste, ausgeschrieben im Menü) + Dark-Mode
    top_flows = slice_(pages[page_url("flows", lang)], "<nav class=top", "</nav>")
    assert 'id=ts-theme' in top_flows, "Dark-Mode-Knopf fehlt"
    assert f">{lang.upper()}<" in top_flows, "Sprachkürzel fehlt"
    for label in ("English", "Deutsch"):
        assert label in top_flows, "Sprachen im Menü ausgeschrieben"

    # nav2 ohne Trennlinie oben, Dropdown-Einträge untereinander
    assert "border-top" not in bars2[0]

# Startseite: schmaler, ohne Marke in der ersten Leiste
idx = pages[page_url("index", "en")]
assert "--nav-w:720px" in idx and "nobrand" in slice_(idx, "<nav class='top nobrand'", "</nav>")
assert "class=brand" in pages[page_url("flows", "en")]
assert "nobrand" in nav_top("x", brand_href=None) and "class=brand" in nav_top("x")
print("  nav1 (Marke + Werkzeuge), nav2, Fußzeile — überall dieselben; Startseite ohne Marke")

print("OK test_site")

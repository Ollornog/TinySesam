"""Die statische Flow-Seite muss zu examples/flows.py passen — sonst zeigt GitHub Pages Altes."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "examples"))

from flows import FLOWS, render  # noqa: E402

# Jeder Flow hat beide Sprachen und die Pflichtfelder
for f in FLOWS:
    assert f["key"] and f["config"] and callable(f["active"]), f
    for lang in ("de", "en"):
        loc = f[lang]
        assert loc["title"] and loc["why"] and loc["steps"], (f["key"], lang)
        for kind, _text in loc["steps"]:
            assert kind in ("do", "srv", "end"), (f["key"], lang, kind)
print(f"  {len(FLOWS)} Flows, beide Sprachen, Kästchen-Typen ok")

# Statische Seite ist aktuell: neu bauen und mit der eingecheckten Datei vergleichen
page = os.path.join(ROOT, "docs", "flows.html")
with open(page, encoding="utf-8") as fh:
    before = fh.read()
subprocess.run([sys.executable, os.path.join(ROOT, "tools", "build_flows.py")],
               check=True, capture_output=True)
with open(page, encoding="utf-8") as fh:
    after = fh.read()
assert before == after, ("docs/flows.html ist veraltet — `python tools/build_flows.py` laufen lassen "
                        "und das Ergebnis mitcommitten.")
print("  docs/flows.html ist aktuell (aus flows.py gebaut)")

# Statisch: Config-Schalter statt aktiv/aus. Mit cfg: Markierung.
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

print("OK test_flows_page")

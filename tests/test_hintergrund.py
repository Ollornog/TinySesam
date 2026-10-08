"""Hintergrundbilder und Standard-Favicon (0.24.8).

- Ohne `brand_icon` traegt jede eingebaute Seite ein eingebautes Favicon (data:-URI); `brand_icon="none"` schaltet ab.
- `brand_backgrounds` legt rotierende, sehr dunkel abgedeckte Bilder hinter die Seite — im nonce-geschuetzten
  Seiten-<style>, nie als style=-Attribut (die strenge CSP verbietet das). Eine https-Adresse gibt die strenge CSP fuer
  genau diese Herkunft frei, sonst nichts.
"""
import os
import re
import tempfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, gateway


def ok(name):
    print(f"  ✓ {name}")


def auth(**kw):
    return TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", passkey_enabled=False,
                                     db_path=os.path.join(tempfile.mkdtemp(), "t.db"), **kw))


def seite(a, pfad="/auth/login"):
    app = FastAPI(); app.include_router(a.router())
    return TestClient(app).get(pfad)


r = seite(auth())
assert re.search(r"<link rel=icon href='data:image/svg\+xml;base64,[A-Za-z0-9+/=]+'>", r.text)
assert "tsbg" not in r.text and "bilder.example.com" not in r.headers.get("content-security-policy", "")
ok("ohne Einstellung: eingebautes Favicon, kein Hintergrund, CSP unverändert")
assert "rel=icon" not in seite(auth(brand_icon="none")).text
ok("brand_icon='none' schaltet das Favicon ab")

BILDER = ["https://bilder.example.com/a.jpg?w=1920&q=60", "/bg/b.jpg", "https://cdn.example.com/c.jpg"]
r = seite(auth(brand_backgrounds=BILDER, brand_background_credit_text="Fotos: Beispiel",
               brand_background_credit_url="https://example.com/"))
h = r.text
assert h.count("<i></i>") == 3 and "<div class=tsbg aria-hidden=true>" in h
assert "style=" not in h.split("<body>", 1)[1], "Inline-style im Body — die strenge CSP blockt das"
for k, b in enumerate(BILDER, 1):
    assert f".tsbg i:nth-child({k}){{background-image:url('{b}')" in h, b
assert "@keyframes tsbg" in h and "prefers-reduced-motion:reduce" in h
assert "<a class=tsbg-quelle href='https://example.com/' target=_blank rel='noopener noreferrer'>Fotos: Beispiel</a>" in h
ok("drei Bilder: Ebenen, Bilder im <style>, Überblenden, reduzierte Bewegung, Quellenlink unten rechts")
csp = r.headers["content-security-policy"]
assert "img-src 'self' data: https://bilder.example.com https://cdn.example.com;" in csp, csp
assert "script-src 'nonce-" in csp and "'unsafe-inline'" not in csp
ok("CSP: img-src um genau die beiden fremden Herkünfte erweitert, sonst streng wie vorher")

h1 = seite(auth(brand_backgrounds=["/bg/eins.jpg"])).text
assert "@keyframes" not in h1 and ".tsbg i{opacity:.32}" in h1
ok("ein Bild: steht still, ohne Animation")

for boese in ("https://x.example/a.jpg') ;}body{display:none", "javascript:alert(1)", "//x.example/a.jpg", "a b.jpg"):
    try:
        auth(brand_backgrounds=[boese]); assert False, boese
    except Exception as e:
        assert "brand_backgrounds" in str(e), (boese, e)
for boese in ("javascript:alert(1)",):
    try:
        auth(brand_background_credit_text="x", brand_background_credit_url=boese); assert False
    except Exception as e:
        assert "credit_url" in str(e)
ok("Konfiguration: CSS-Ausbruch, javascript:, //, Leerzeichen und ein javascript:-Link werden abgewiesen")

h = seite(auth(brand_backgrounds=["/a.jpg"], brand_background_credit_text="<b>x</b>",
               brand_background_credit_url="https://e.example/?a=1&b=2")).text
assert "<b>x</b>" not in h and "&lt;b&gt;x&lt;/b&gt;" in h and "a=1&amp;b=2" in h
ok("Quellenhinweis maskiert")

# Gateway: fremde Adressen nur mit ausdrücklicher Freigabe.
for k in [k for k in os.environ if k.startswith("TINYSESAM_")]:
    del os.environ[k]
os.environ.update({"TINYSESAM_BASE_URL": "https://auth.example.com", "TINYSESAM_OIDC_ISSUER": "https://id.example.com",
                   "TINYSESAM_OIDC_CLIENT_ID": "x", "TINYSESAM_OIDC_CLIENT_SECRET": "y",
                   "TINYSESAM_BRAND_BACKGROUNDS": "/bg/a.jpg https://bilder.example.com/b.jpg"})
try:
    gateway.config_from_env(); assert False, "fremde Adresse ohne Freigabe angenommen"
except SystemExit as e:
    assert "TINYSESAM_BRAND_BACKGROUNDS_EXTERN" in str(e)
os.environ["TINYSESAM_BRAND_BACKGROUNDS_EXTERN"] = "1"
c = gateway.config_from_env()
assert c.brand_backgrounds == ["/bg/a.jpg", "https://bilder.example.com/b.jpg"]
os.environ["TINYSESAM_BRAND_BACKGROUNDS"] = "/bg/a.jpg"
del os.environ["TINYSESAM_BRAND_BACKGROUNDS_EXTERN"]
assert gateway.config_from_env().brand_backgrounds == ["/bg/a.jpg"]
ok("Gateway: https-Bilder nur mit TINYSESAM_BRAND_BACKGROUNDS_EXTERN=1, eigene Pfade immer")
print("Hintergrund OK")

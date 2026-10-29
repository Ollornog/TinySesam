"""Background images and default favicon (0.24.8).

- Without `brand_icon` every built-in page carries a built-in favicon (data: URI); `brand_icon="none"` switches it off.
- `brand_backgrounds` puts rotating, very darkly covered images behind the page — in the nonce-protected
  page <style>, never as a style= attribute (the strict CSP forbids that). An https address releases the strict CSP for
  exactly this origin, nothing else.
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


def page_html(a, path="/auth/login"):
    app = FastAPI(); app.include_router(a.router())
    return TestClient(app).get(path)


r = page_html(auth())
assert re.search(r"<link rel=icon href='data:image/svg\+xml;base64,[A-Za-z0-9+/=]+'>", r.text)
assert "tsbg" not in r.text and "bilder.example.com" not in r.headers.get("content-security-policy", "")
ok("without setting: built-in favicon, no background, CSP unchanged")
assert "rel=icon" not in page_html(auth(brand_icon="none")).text
ok("brand_icon='none' switches the favicon off")

IMAGES = ["https://bilder.example.com/a.jpg?w=1920&q=60", "/bg/b.jpg", "https://cdn.example.com/c.jpg"]
r = page_html(auth(brand_backgrounds=IMAGES, brand_background_credit_text="Fotos: Beispiel",
               brand_background_credit_url="https://example.com/"))
h = r.text
assert h.count("<i></i>") == 3 and "<div class=tsbg aria-hidden=true>" in h
assert "style=" not in h.split("<body>", 1)[1], "inline style in the body — the strict CSP blocks that"
for k, b in enumerate(IMAGES, 1):
    assert f".tsbg i:nth-child({k}){{background-image:url('{b}')" in h, b
assert "@keyframes tsbg" in h and "prefers-reduced-motion:reduce" in h
assert "<a class=tsbg-source href='https://example.com/' target=_blank rel='noopener noreferrer'>Fotos: Beispiel</a>" in h
ok("three images: layers, images in <style>, cross-fade, reduced motion, source link bottom right")
csp = r.headers["content-security-policy"]
assert "img-src 'self' data: https://bilder.example.com https://cdn.example.com;" in csp, csp
assert "script-src 'nonce-" in csp and "'unsafe-inline'" not in csp
ok("CSP: img-src extended by exactly the two foreign origins, otherwise strict as before")

h1 = page_html(auth(brand_backgrounds=["/bg/eins.jpg"])).text
assert "@keyframes" not in h1 and ".tsbg i{opacity:var(--ts-image-strength)}" in h1
ok("one image: stands still, without animation")

for evil in ("https://x.example/a.jpg') ;}body{display:none", "javascript:alert(1)", "//x.example/a.jpg", "a b.jpg"):
    try:
        auth(brand_backgrounds=[evil]); assert False, evil
    except Exception as e:
        assert "brand_backgrounds" in str(e), (evil, e)
for evil in ("javascript:alert(1)",):
    try:
        auth(brand_background_credit_text="x", brand_background_credit_url=evil); assert False
    except Exception as e:
        assert "credit_url" in str(e)
ok("configuration: CSS breakout, javascript:, //, whitespace and a javascript: link are rejected")

h = page_html(auth(brand_backgrounds=["/a.jpg"], brand_background_credit_text="<b>x</b>",
               brand_background_credit_url="https://e.example/?a=1&b=2")).text
assert "<b>x</b>" not in h and "&lt;b&gt;x&lt;/b&gt;" in h and "a=1&amp;b=2" in h
ok("source note escaped")

# Gateway: foreign addresses only with explicit approval.
for k in [k for k in os.environ if k.startswith("TINYSESAM_")]:
    del os.environ[k]
os.environ.update({"TINYSESAM_BASE_URL": "https://auth.example.com", "TINYSESAM_OIDC_ISSUER": "https://id.example.com",
                   "TINYSESAM_OIDC_CLIENT_ID": "x", "TINYSESAM_OIDC_CLIENT_SECRET": "y",
                   "TINYSESAM_BRAND_BACKGROUNDS": "/bg/a.jpg https://bilder.example.com/b.jpg"})
try:
    gateway.config_from_env(); assert False, "foreign address accepted without approval"
except SystemExit as e:
    assert "TINYSESAM_BRAND_BACKGROUNDS_EXTERN" in str(e)
os.environ["TINYSESAM_BRAND_BACKGROUNDS_EXTERN"] = "1"
c = gateway.config_from_env()
assert c.brand_backgrounds == ["/bg/a.jpg", "https://bilder.example.com/b.jpg"]
os.environ["TINYSESAM_BRAND_BACKGROUNDS"] = "/bg/a.jpg"
del os.environ["TINYSESAM_BRAND_BACKGROUNDS_EXTERN"]
assert gateway.config_from_env().brand_backgrounds == ["/bg/a.jpg"]
ok("gateway: https images only with TINYSESAM_BRAND_BACKGROUNDS_EXTERN=1, own paths always")
print("Hintergrund OK")

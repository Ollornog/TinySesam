"""Brand before the applications (0.24.7): `gate_brand` sets “Anmelden bei <Marke>” as the heading and names the application
below it (“App: <Name>”). Without a brand it stays at “Anmelden bei <Anwendung>” — existing gateways see nothing new."""
import os
import re
import tempfile

from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


def auth_mit(marke=""):
    return TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", gate_brand=marke, rp_name="Probe",
                                     db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False))


def kopf(html):
    h1 = re.search(r"<h1>([^<]*)</h1>", html).group(1)
    app = re.search(r"<p class=app>([^<]*)</p>", html)
    return h1, (app.group(1) if app else None)


ohne = auth_mit("")
assert kopf(ohne.render_page("login", next="/", app_name="Paperless").body.decode()) == ("Anmelden bei Paperless", None)
assert kopf(ohne.render_page("login", next="/").body.decode()) == ("Probe", None)
ok("without brand: “Anmelden bei <Anwendung>”, without app line (as before)")

mit = auth_mit("Firma A")
assert kopf(mit.render_page("login", next="/", app_name="Paperless").body.decode()) == ("Anmelden bei Firma A", "App: Paperless")
assert kopf(mit.render_page("login", next="/").body.decode()) == ("Anmelden bei Firma A", None)
ok("with brand: “Anmelden bei <Marke>”, below it “App: <Name>”; without application no empty line")

titel = lambda h: re.search(r"<title>([^<]*)</title>", h).group(1)
assert titel(mit.render_page("login", next="/", app_name="Paperless").body.decode()) == "Firma A Login"
assert titel(ohne.render_page("login", next="/", app_name="Paperless").body.decode()) == "Anmelden"
ok("page title: with brand “<Marke> Login”, without it stays “Anmelden”")

ikon = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", gate_brand="Firma A", brand_icon="data:image/svg+xml;base64,PHN2Zy8+",
                                 db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False))
for seite, ctx in (("login", {"next": "/", "app_name": "Paperless"}), ("gate_logged_out", {"app_name": "Paperless"})):
    assert "<link rel=icon href='data:image/svg+xml;base64,PHN2Zy8+'>" in ikon.render_page(seite, **ctx).body.decode(), seite
ok("favicon (brand_icon) is on the sign-in page and the signed-out page")

boese = auth_mit("<b>x</b>")
html = boese.render_page("login", next="/", app_name="<i>y</i>").body.decode()
assert "<b>x</b>" not in html and "<i>y</i>" not in html and "&lt;b&gt;x&lt;/b&gt;" in html and "&lt;i&gt;y&lt;/i&gt;" in html
ok("brand and app name are masked")
print("Gate-Marke OK")

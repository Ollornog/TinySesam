"""Meldungen (0.24.6): Hinweise, Erfolg, Warnungen und Fehler stehen als eigene Kästen UNTER der Karte, je mit Symbol.

Bis 0.24.5 stand jede Seite ihre Fehlerzeile selbst in die Karte (`<div class=err>`), Erfolg als `class=ok`, die
Anmeldeseite den Hinweis nach dem Abmelden als graue Zeile. Geprüft wird je Seite: Der Text steht NICHT in der Karte,
sondern im Kasten `.meldungen` dahinter, mit Art und Symbol; ohne Meldung gibt es keinen leeren Kasten.
"""
import os
import re
import tempfile

from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


auth = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="de", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), rp_name="Meldungen",
    passkey_enabled=False, pin_enabled=True, magiclink_enabled=True, password_reset_enabled=True,
    allow_signup=True, totp_enabled=True, resource_locks_enabled=True, base_url="https://auth.example.com"))

PROBE = "Probe-Meldung 4711"


def zerlegen(html: str):
    """(Karte, Rest nach der Karte) — die Karte ist das erste <div class=card>…, die Meldungen folgen ihr."""
    i = html.index("<div class=card>")
    j = html.index("<div class=meldungen>") if "<div class=meldungen>" in html else len(html)
    karte = html[i:j]
    # Die Karte muss VOR dem Kasten geschlossen sein — sonst stünden die Meldungen in ihr (gleich viele <div wie </div>).
    if j < len(html):
        assert karte.count("<div") == karte.count("</div>"), "Meldungen stehen IN der Karte, nicht darunter"
    return karte, html[j:]


def seite(seitenname, **ctx):
    return auth.render_page(seitenname, **ctx).body.decode()


# ---------- Fehler auf jeder Seite ----------
FEHLER_SEITEN = {
    "login": {"next": "/"}, "totp": {"next": "/"}, "register": {"next": "/"}, "magic_request": {"next": "/"},
    "forgot": {}, "reset": {"token": "x"}, "reauth": {"next": "/"}, "pin": {"next": "/"},
    "resource_unlock": {"name": "tresor", "kind": "pin", "label": "Tresor", "next": "/"},
}
for name, ctx in FEHLER_SEITEN.items():
    html = seite(name, error=PROBE, **ctx)
    karte, rest = zerlegen(html)
    assert PROBE not in karte, f"{name}: Fehler steht noch in der Karte"
    m = re.search(r"<div class='meldung fehler' role=alert><svg[^>]*>.*?</svg><span>([^<]*)</span></div>", rest)
    assert m and m.group(1) == PROBE, f"{name}: keine Fehler-Meldung mit Symbol unter der Karte"
    assert "class=err" not in html, f"{name}: alte Fehlerzeile"
    leer = seite(name, **ctx)
    assert "<div class=meldungen>" not in leer, f"{name}: leerer Meldungskasten ohne Meldung"
ok(f"Fehler auf {len(FEHLER_SEITEN)} Seiten: als Meldung mit Symbol unter der Karte, keine in der Karte, kein leerer Kasten")

# ---------- Erfolg und „Link ungültig“ ----------
for name, ctx, art, schluessel in (
        ("register", {"next": "/", "sent_verify": True}, "ok", "reg.verify"),
        ("magic_request", {"next": "/", "sent": True}, "ok", "magic.sent"),
        ("forgot", {"sent": True}, "ok", "magic.sent"),
        ("magic_invalid", {}, "fehler", "magic.invalid")):
    html = seite(name, **ctx)
    karte, rest = zerlegen(html)
    text = auth.t(schluessel)
    assert text not in karte and f"<div class='meldung {art}'" in rest and text in rest, f"{name}: {art}-Meldung"
    assert "class=ok>" not in html, f"{name}: alte Erfolgszeile"
ok("Erfolg (Registrierung, Login-Link, Reset-Link) und „Link ungültig“ als Meldung unter der Karte")

# ---------- Anmeldeseite: alle Arten, in fester Reihenfolge ----------
html = seite("login", next="/", info="I-Text", warn="W-Text", error="F-Text")
karte, rest = zerlegen(html)
arten = re.findall(r"<div class='meldung (\w+)'", rest)
assert arten == ["info", "warn", "fehler"], arten
assert all(t not in karte for t in ("I-Text", "W-Text", "F-Text"))
assert html.count("<svg") >= 3 and "role=status" in rest and "role=alert" in rest
ok("Anmeldeseite: Hinweis, Warnung, Fehler je als eigener Kasten, Reihenfolge info → warn → fehler, mit Rolle")

# ---------- der Text wird maskiert ----------
html = seite("login", next="/", error="<script>x</script>")
assert "<script>x</script>" not in html and "&lt;script&gt;" in html
ok("Meldungstext wird maskiert")

print("Meldungen OK")

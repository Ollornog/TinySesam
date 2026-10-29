"""Messages (0.24.6): notices, success, warnings and errors appear as boxes of their own BELOW the card, each with a symbol.

Until 0.24.5 every page put its error line into the card itself (`<div class=err>`), success as `class=ok`, the
sign-in page the notice after signing out as a grey line. Checked per page: the text is NOT in the card,
but in the box `.meldungen` behind it, with kind and symbol; without a message there is no empty box.
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
    """(card, rest after the card) — the card is the first <div class=card>…, the messages follow it."""
    i = html.index("<div class=card>")
    j = html.index("<div class=meldungen>") if "<div class=meldungen>" in html else len(html)
    karte = html[i:j]
    # The card must be closed BEFORE the box — otherwise the messages would be inside it (equally many <div as </div>).
    if j < len(html):
        assert karte.count("<div") == karte.count("</div>"), "messages are IN the card, not below it"
    return karte, html[j:]


def seite(seitenname, **ctx):
    return auth.render_page(seitenname, **ctx).body.decode()


# ---------- Error on every page ----------
FEHLER_SEITEN = {
    "login": {"next": "/"}, "totp": {"next": "/"}, "register": {"next": "/"}, "magic_request": {"next": "/"},
    "forgot": {}, "reset": {"token": "x"}, "reauth": {"next": "/"}, "pin": {"next": "/"},
    "resource_unlock": {"name": "tresor", "kind": "pin", "label": "Vault", "next": "/"},
}
for name, ctx in FEHLER_SEITEN.items():
    html = seite(name, error=PROBE, **ctx)
    karte, rest = zerlegen(html)
    assert PROBE not in karte, f"{name}: error is still in the card"
    m = re.search(r"<div class='meldung fehler' role=alert><svg[^>]*>.*?</svg><span>([^<]*)</span></div>", rest)
    assert m and m.group(1) == PROBE, f"{name}: no error message with symbol below the card"
    assert "class=err" not in html, f"{name}: alte Fehlerzeile"
    leer = seite(name, **ctx)
    assert "<div class=meldungen>" not in leer, f"{name}: empty message box without a message"
ok(f"errors on {len(FEHLER_SEITEN)} pages: as message with symbol below the card, none in the card, no empty box")

# ---------- Success and “Link ungültig” ----------
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
ok("success (registration, login link, reset link) and “Link ungültig” as message below the card")

# ---------- Sign-in page: all kinds, in fixed order ----------
html = seite("login", next="/", info="I-Text", warn="W-Text", error="F-Text")
karte, rest = zerlegen(html)
arten = re.findall(r"<div class='meldung (\w+)'", rest)
assert arten == ["info", "warn", "fehler"], arten
assert all(t not in karte for t in ("I-Text", "W-Text", "F-Text"))
assert html.count("<svg") >= 3 and "role=status" in rest and "role=alert" in rest
ok("sign-in page: notice, warning, error each as a box of its own, order info → warn → fehler, with role")

# ---------- the text is masked ----------
html = seite("login", next="/", error="<script>x</script>")
assert "<script>x</script>" not in html and "&lt;script&gt;" in html
ok("message text is masked")

print("Meldungen OK")

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


def split(html: str):
    """(card, rest after the card) — the card is the first <div class=card>…, the messages follow it."""
    i = html.index("<div class=card>")
    j = html.index("<div class=meldungen>") if "<div class=meldungen>" in html else len(html)
    mapping = html[i:j]
    # The card must be closed BEFORE the box — otherwise the messages would be inside it (equally many <div as </div>).
    if j < len(html):
        assert mapping.count("<div") == mapping.count("</div>"), "messages are IN the card, not below it"
    return mapping, html[j:]


def page_html(page_name, **ctx):
    return auth.render_page(page_name, **ctx).body.decode()


# ---------- Error on every page ----------
ERROR_PAGES = {
    "login": {"next": "/"}, "totp": {"next": "/"}, "register": {"next": "/"}, "magic_request": {"next": "/"},
    "forgot": {}, "reset": {"token": "x"}, "reauth": {"next": "/"}, "pin": {"next": "/"},
    "resource_unlock": {"name": "tresor", "kind": "pin", "label": "Vault", "next": "/"},
}
for name, ctx in ERROR_PAGES.items():
    html = page_html(name, error=PROBE, **ctx)
    mapping, rest = split(html)
    assert PROBE not in mapping, f"{name}: error is still in the card"
    m = re.search(r"<div class='meldung fehler' role=alert><svg[^>]*>.*?</svg><span>([^<]*)</span></div>", rest)
    assert m and m.group(1) == PROBE, f"{name}: no error message with symbol below the card"
    assert "class=err" not in html, f"{name}: alte Fehlerzeile"
    empty = page_html(name, **ctx)
    assert "<div class=meldungen>" not in empty, f"{name}: empty message box without a message"
ok(f"errors on {len(ERROR_PAGES)} pages: as message with symbol below the card, none in the card, no empty box")

# ---------- Success and “Link ungültig” ----------
for name, ctx, kind, key_name in (
        ("register", {"next": "/", "sent_verify": True}, "ok", "reg.verify"),
        ("magic_request", {"next": "/", "sent": True}, "ok", "magic.sent"),
        ("forgot", {"sent": True}, "ok", "magic.sent"),
        ("magic_invalid", {}, "fehler", "magic.invalid")):
    html = page_html(name, **ctx)
    mapping, rest = split(html)
    text = auth.t(key_name)
    assert text not in mapping and f"<div class='meldung {kind}'" in rest and text in rest, f"{name}: {kind}-Meldung"
    assert "class=ok>" not in html, f"{name}: alte Erfolgszeile"
ok("success (registration, login link, reset link) and “Link ungültig” as message below the card")

# ---------- Sign-in page: all kinds, in fixed order ----------
html = page_html("login", next="/", info="I-Text", warn="W-Text", error="F-Text")
mapping, rest = split(html)
kinds = re.findall(r"<div class='meldung (\w+)'", rest)
assert kinds == ["info", "warn", "fehler"], kinds
assert all(t not in mapping for t in ("I-Text", "W-Text", "F-Text"))
assert html.count("<svg") >= 3 and "role=status" in rest and "role=alert" in rest
ok("sign-in page: notice, warning, error each as a box of its own, order info → warn → fehler, with role")

# ---------- the text is masked ----------
html = page_html("login", next="/", error="<script>x</script>")
assert "<script>x</script>" not in html and "&lt;script&gt;" in html
ok("message text is masked")

print("Meldungen OK")

"""B-3: the `next` target on the login page travels as ONE query value.

The page puts `next` into links (`/auth/magic/request?next=…`, `/auth/register?next=…`, the OIDC and SAML buttons) and
into the passkey script. It used to HTML-escape it only. A character with a meaning of its own in a query string then
changed the target on the way: `&` cut the target off (`/a?x=1&y=2` lost `&y=2`), `+` came back as a space, `%3B` as `;`,
and `&amp;` in a file name went through the escaping twice. The person landed on another file than the one requested.

Every target below must come out of the link exactly as it went in. The open-redirect check stays where it was:
a foreign host is still `/` after decoding.
"""
import os
import re
import tempfile
from html import unescape
from urllib.parse import parse_qs

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


APP = "https://app.example.com"
auth = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), rp_name="Test",
    passkey_enabled=False, oidc_enabled=False, cookie_secure=False, magiclink_enabled=True, allow_signup=True,
    forward_auth_enabled=True, base_url="https://auth.example.com", cookie_domain=".example.com",
    trusted_redirect_hosts=["app.example.com"]))
fa = FastAPI()
fa.include_router(auth.router())
c = TestClient(fa)

ZIELE = [
    APP + "/a;b.pdf",
    APP + "/a%3Bb.pdf",
    APP + "/Tom&amp;Jerry.pdf",
    APP + "/a?x=1&y=2",
    APP + "/a+b.pdf",
    APP + "/a%2Fb%25c.pdf",
    APP + "/x?k=%3B&m=a;b#frag",
    APP + "/d/it's \"quoted\" <b>.pdf",
]


# The passkey script needs the passkey method switched on but not its routes: render the page directly, without a router
# (the router would need the `webauthn` extra, which the narrow CI run does not have).
auth_pk = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "pk.db"), rp_name="Test",
    passkey_enabled=True, oidc_enabled=False, cookie_secure=False, base_url="https://auth.example.com"))


def seite_pk(ziel):
    return auth_pk.render_page("login", next=ziel).body.decode("utf-8")


def links(seite):
    """The `next` value of every link/script string on the login page — decoded the way a server decodes a query."""
    treffer = re.findall(r"""(?:href='[^']*[?&]next=([^'&]*)'|finish\?next=([^'"&\s]*))""", seite)
    return [parse_qs("next=" + unescape(a or b), keep_blank_values=True)["next"][0] for a, b in treffer]


for ziel in ZIELE:
    seite = c.get("/auth/login", params={"next": ziel}).text
    gefunden = links(seite)
    # magic link and register link
    assert len(gefunden) == 2, (ziel, gefunden)
    assert all(g == ziel for g in gefunden), (ziel, gefunden)
    skript = links(seite_pk(ziel))
    assert len(skript) == 1 and skript[0] == ziel, (ziel, skript)
ok(f"{len(ZIELE)} targets with ; %3B &amp; & + % # quotes: every link and the passkey script carry them unchanged")

# The way the browser goes: take the link from the page, follow it, read the target the next page puts into its form.
for ziel in ZIELE[:5]:
    seite = c.get("/auth/login", params={"next": ziel}).text
    href = unescape(re.search(r"href='(__TS_P__)?(/auth/register\?next=[^']*)'", seite.replace("__TS_P__", "")).group(2))
    folge = c.get(href).text
    wert = unescape(re.search(r"name=next value='([^']*)'", folge).group(1))
    assert wert == ziel, (ziel, wert)
ok("the register page reached through the link has the same target in its form (round trip)")

# Encoding must not loosen the open-redirect check: decoded, a foreign target is still refused.
for boese in ["https://evil.example/x", "//evil.example/x", "https://app.example.com.evil.example/x", "\\\\evil"]:
    seite = c.get("/auth/login", params={"next": boese}).text
    gefunden = links(seite)
    assert gefunden, boese
    for g in gefunden:
        assert g == "/", (boese, g)
ok("foreign hosts, // and backslash: the page never offers them in a link (still `/`)")

# And the characters themselves are encoded, not only decodable by luck: nothing but [A-Za-z0-9_.~%-] after `next=`.
seite = c.get("/auth/login", params={"next": ZIELE[3]}).text
roh = re.findall(r"""next=([^'"\s]*)""", seite)
assert roh and all(re.fullmatch(r"[A-Za-z0-9_.~%-]*", r) for r in roh), roh
ok("the value after `next=` is plain percent-encoding — safe in an attribute and in a script string")

print("next in links OK")

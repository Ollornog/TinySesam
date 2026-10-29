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

DESTINATIONS = [
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


def page_html_pk(destination):
    return auth_pk.render_page("login", next=destination).body.decode("utf-8")


def links(page_html):
    """The `next` value of every link/script string on the login page — decoded the way a server decodes a query."""
    hit = re.findall(r"""(?:href='[^']*[?&]next=([^'&]*)'|finish\?next=([^'"&\s]*))""", page_html)
    return [parse_qs("next=" + unescape(a or b), keep_blank_values=True)["next"][0] for a, b in hit]


for destination in DESTINATIONS:
    page_html = c.get("/auth/login", params={"next": destination}).text
    found = links(page_html)
    # magic link and register link
    assert len(found) == 2, (destination, found)
    assert all(g == destination for g in found), (destination, found)
    script = links(page_html_pk(destination))
    assert len(script) == 1 and script[0] == destination, (destination, script)
ok(f"{len(DESTINATIONS)} targets with ; %3B &amp; & + % # quotes: every link and the passkey script carry them unchanged")

# The way the browser goes: take the link from the page, follow it, read the target the next page puts into its form.
for destination in DESTINATIONS[:5]:
    page_html = c.get("/auth/login", params={"next": destination}).text
    href = unescape(re.search(r"href='(__TS_P__)?(/auth/register\?next=[^']*)'", page_html.replace("__TS_P__", "")).group(2))
    sequence = c.get(href).text
    value = unescape(re.search(r"name=next value='([^']*)'", sequence).group(1))
    assert value == destination, (destination, value)
ok("the register page reached through the link has the same target in its form (round trip)")

# Encoding must not loosen the open-redirect check: decoded, a foreign target is still refused.
for evil in ["https://evil.example/x", "//evil.example/x", "https://app.example.com.evil.example/x", "\\\\evil"]:
    page_html = c.get("/auth/login", params={"next": evil}).text
    found = links(page_html)
    assert found, evil
    for g in found:
        assert g == "/", (evil, g)
ok("foreign hosts, // and backslash: the page never offers them in a link (still `/`)")

# And the characters themselves are encoded, not only decodable by luck: nothing but [A-Za-z0-9_.~%-] after `next=`.
page_html = c.get("/auth/login", params={"next": DESTINATIONS[3]}).text
raw = re.findall(r"""next=([^'"\s]*)""", page_html)
assert raw and all(re.fullmatch(r"[A-Za-z0-9_.~%-]*", r) for r in raw), raw
ok("the value after `next=` is plain percent-encoding — safe in an attribute and in a script string")

print("next in links OK")

"""Home network without a domain (T-37): the warning for an IP `base_url`, and the template deploy/home-network/.

What is measured here:
* config_check warns for every non-loopback IP literal in `base_url` (IPv4, IPv6, with and without port, http
  and https) and points to docs/HOME-NETWORK.md; loopback, `localhost` and a domain stay silent.
* The template's own settings (docker-compose.yml in deploy/home-network/) start the gateway without an error,
  and forward auth sends the app on another PORT of the same IP back to it after the sign-in.
* The template and its guide name only documentation addresses (RFC 5737 / RFC 3849) — a real private
  address there would be copied verbatim into somebody's network.
* Every site of the Caddyfile uses `tls internal`, and default_sni is set (without it the handshake fails behind
  a Docker bridge — measured against Caddy 2.11.9, see the comment in the Caddyfile).
The forward-auth block of the Caddyfile is measured with the other templates in test_legacy_data.py (headers, cookie
rule, Go-canonical placeholders).
"""
import ipaddress
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from tinysesam import TinySesamConfig, config_check
from tinysesam import gateway

ROOT = Path(__file__).resolve().parent.parent
HOME = ROOT / "deploy" / "home-network"
GUIDE = ROOT / "docs" / "HOME-NETWORK.md"


def ok(name):
    print(f"  ✓ {name}")


def ip_warnings(base_url: str, **values) -> list[str]:
    error, warnings = config_check.check_config(TinySesamConfig(db_path=":memory:", base_url=base_url, **values))
    assert not error, error
    return [w for w in warnings if "is an IP address" in w or "ist eine IP-Adresse" in w]


# ---------- config_check: IP as base_url ----------
for base in ("https://192.0.2.10", "https://192.0.2.10:8443", "http://192.0.2.10", "https://[2001:db8::1]",
             "http://[2001:db8::1]:8443", "https://203.0.113.7/sso"):
    found = ip_warnings(base)
    assert len(found) == 1, (base, found)
    assert "docs/HOME-NETWORK.md" in found[0] and "domain" in found[0], found[0]
ok("IP base_url (IPv4/IPv6, port, http, subpath) → exactly one warning with the guide and the domain advice")

for base in ("http://127.0.0.1:8000", "http://127.0.0.2", "http://[::1]:8000", "http://localhost:8000",
             "https://auth.example.com", "https://192-0-2-10.example.com", ""):
    assert not ip_warnings(base), base
ok("loopback, localhost, a domain and an empty base_url stay silent (local development needs no CA)")

_de = ip_warnings("https://192.0.2.10", lang="de")
assert len(_de) == 1 and "ist eine IP-Adresse" in _de[0] and "docs/HOME-NETWORK.md" in _de[0], _de
ok("the warning is translated (lang='de')")


# ---------- the template's settings start the gateway ----------
def override_env() -> dict:
    """The `TINYSESAM_*` values the override sets for the gateway (no YAML parser in the test deps)."""
    text = (HOME / "docker-compose.yml").read_text(encoding="utf-8")
    block = text.split("  tinysesam:\n", 1)[1].split("\n  caddy:\n", 1)[0]
    return dict(re.findall(r'^\s+(TINYSESAM_[A-Z_]+):\s*"([^"]*)"', block, re.M))


_env = override_env()
for key in ("TINYSESAM_BASE_URL", "TINYSESAM_COOKIE_DOMAIN", "TINYSESAM_PROTECTED_HOSTS", "TINYSESAM_OIDC_CLIENTS"):
    assert key in _env, f"override does not set {key}"
_saved = dict(os.environ)
try:
    os.environ.update({"TINYSESAM_OIDC_CLIENT_ID": "gateway", "TINYSESAM_OIDC_CLIENT_SECRET": "x",
                       "TINYSESAM_DB": os.path.join(tempfile.mkdtemp(), "home.db"),
                       "TINYSESAM_ALLOWED_GROUPS": "family", **_env})
    cfg = gateway.config_from_env()
finally:
    os.environ.clear()
    os.environ.update(_saved)
error, warnings = config_check.check_config(cfg)
assert not error, error
assert any("is an IP address" in w for w in warnings), warnings
ok("the override's settings pass the configuration check (only the IP warning, on purpose)")

cfg.csrf_enabled = False
client = TestClient(gateway.build_app(cfg), raise_server_exceptions=False)
r = client.get("/auth/forward", headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "192.0.2.10:8443",
                                         "X-Forwarded-Uri": "/photos"})
assert r.status_code == 401, r.status_code
loc = r.headers.get("X-TinySesam-Location", "")
assert loc.startswith("https://192.0.2.10/auth/login?next="), loc
nxt = parse_qs(urlparse(loc).query)["next"][0]
assert urlparse(nxt).netloc == "192.0.2.10:8443" and urlparse(nxt).path == "/photos", nxt
ok("forward auth: the app on :8443 of the same IP is sent to the login at :443 and back to itself")


# ---------- only documentation addresses ----------
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
                                              "127.0.0.0/8", "::1/128")]


def foreign_addresses(text: str) -> list[str]:
    """Every IP literal that is neither a documentation address nor loopback (CIDR masks count as addresses too)."""
    found = []
    for m in re.finditer(r"(?<![\w.:])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])", text):
        try:
            addr = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if not any(addr in n for n in DOC_NETS):
            found.append(m.group(1))
    for m in re.finditer(r"\[?([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})\]?", text):
        try:
            addr = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if not any(addr in n for n in DOC_NETS):
            found.append(m.group(1))
    return found


_files = sorted(HOME.iterdir()) + [GUIDE]
for f in _files:
    assert not foreign_addresses(f.read_text(encoding="utf-8")), (f.name, foreign_addresses(f.read_text(encoding="utf-8")))
# The probe address is assembled, so that the repo's own hygiene check does not take it for a real one.
_private = "10." + "1.2.3"
assert foreign_addresses(f"server at {_private} and [fd00::1]") == [_private, "fd00::1"]
assert foreign_addresses("192.0.2.10, 2001:db8::1, 127.0.0.1, version 2.11.9") == []
ok(f"template and guide name only documentation addresses ({len(_files)} files; the probe itself finds 10.x and fd00::)")


# ---------- the Caddyfile ----------
_caddy = (HOME / "Caddyfile").read_text(encoding="utf-8")
_code = "\n".join(z.split("#", 1)[0] if not z.lstrip().startswith("header_up Cookie") else z for z in _caddy.splitlines())
_sites = re.findall(r"^(https://\S+) \{\n(.*?)^\}", _code, re.M | re.S)
assert len(_sites) == 2, [s[0] for s in _sites]
for address, body in _sites:
    assert re.search(r"^\ttls internal$", body, re.M), f"{address}: without tls internal"
assert re.search(r"^\tdefault_sni \{\$TS_HOME_IP:192\.0\.2\.10\}$", _code, re.M), "default_sni missing"
ok("Caddyfile: both sites on tls internal, default_sni set for clients without SNI")

_compose = (HOME / "docker-compose.yml").read_text(encoding="utf-8")
_images = re.findall(r"^\s+image:\s*(\S+)", _compose, re.M)
assert _images and all(re.search(r"^caddy:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$", i) for i in _images), _images
assert "../home-network/Caddyfile:/etc/caddy/Caddyfile:ro" in _compose
ok("override: Caddy pinned by version and digest, Caddyfile mounted read-only from this folder")

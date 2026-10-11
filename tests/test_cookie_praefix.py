"""`cookie_prefix` (0.24.12): eine App mit eigenem TinySesam hinter einem TinySesam-Gateway.

Die Proxy-Vorlagen entfernen jedes `tinysesam_*`-Cookie vor der App, damit sie die Sitzung des Gateways nie sieht
(B-20). Eine App, die selbst TinySesam nutzt, verlor dabei ihr OIDC-Flow-Cookie: Der Rückweg vom Provider kam ohne
an und wurde abgewiesen („ohne passendes Flow-Cookie“), man landete wieder beim Login (2026-10-10, paperlaiss-Panel).

  (a) Vorgabe: Namen wie bisher (`tinysesam_session`, `tinysesam_csrf`, `tinysesam_runlock`, Flow-Cookies)
  (b) `cookie_prefix="meineapp_"`: Sitzung, CSRF, Freigabe und die Flow-Cookies von OIDC, SAML, Passkey tragen es
  (c) ausdrücklich gesetzte Namen und `__`-Namen (die Cookies des Gateways) bleiben
  (d) der echte Ablauf: OIDC-Start → Cookie-Kopf durch die Regel aus deploy/forward-auth/Caddyfile.gate → Rückweg.
      Mit Präfix angemeldet; ohne Präfix abgewiesen (Gegenprobe: genau der Fehler aus dem Betrieb)
  (e) Konfigprüfung: kaputtes Präfix → Fehler; ein Gateway (forward_auth_enabled) mit fremdem Präfix → Fehler
"""
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.konfigpruefung import pruefe  # noqa: E402

IDP = "https://idp.example.com"


def ok(text):
    print(f"  ok   {text}")


def _cfg(**k):
    grund = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False, base_url="http://testserver",
                 csrf_enabled=False, passkey_enabled=False)
    grund.update(k)
    return TinySesamConfig(**grund)


class _Claims(dict):
    def validate(self, *a, **k):
        pass


def _oidc_app(**k):
    auth = TinySesam(_cfg(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe", oidc_client_secret="geheim", **k))
    auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize", "token_endpoint": IDP + "/token",
                       "userinfo_endpoint": IDP + "/userinfo", "jwks_uri": IDP + "/jwks"}
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({"sub": "anna-1", "preferred_username": "anna", "email": "anna@example.com", "email_verified": True,
                 "iss": IDP, "nonce": nonce}), {"access_token": "at"})
    auth.oidc.userinfo = lambda at, erwartetes_sub="": {}
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


# Die Regel der Vorlage, wörtlich aus der Datei — ändert sich die Vorlage, prüft dieser Test die neue.
_vorlage = (ROOT / "deploy" / "forward-auth" / "Caddyfile.gate").read_text(encoding="utf-8")
_m = re.search(r'header_up Cookie "([^"]*tinysesam_[^"]*)" ""', _vorlage)
assert _m, "Cookie-Regel in Caddyfile.gate nicht gefunden"
REGEL = re.compile(_m.group(1).replace("\\\\", "\\"))


def _durch_proxy(kopf: str) -> str:
    return re.sub(r"^[;\s]+", "", REGEL.sub("", kopf))


print("cookie_prefix")

# (a)
a = TinySesam(_cfg())
assert (a.session_cookie_name, a.csrf_cookie_name, a.resource_cookie_name) == (
    "tinysesam_session", "tinysesam_csrf", "tinysesam_runlock")
assert a.flow_cookie_name("tinysesam_oidc_flow") == "tinysesam_oidc_flow"
ok("Vorgabe: Namen unverändert")

# (b)
b = TinySesam(_cfg(cookie_prefix="meineapp_"))
assert (b.session_cookie_name, b.csrf_cookie_name, b.resource_cookie_name) == (
    "meineapp_session", "meineapp_csrf", "meineapp_runlock"), (b.session_cookie_name, b.csrf_cookie_name)
for basis, neu in (("tinysesam_oidc_flow", "meineapp_oidc_flow"), ("tinysesam_saml_flow", "meineapp_saml_flow"),
                   ("tinysesam_waflow", "meineapp_waflow")):
    assert b.flow_cookie_name(basis) == neu, b.flow_cookie_name(basis)
hb = TinySesam(_cfg(cookie_prefix="meineapp_", cookie_secure=True))
assert hb.session_cookie_name == "__Host-meineapp_session", hb.session_cookie_name
ok("Präfix: Sitzung, CSRF, Freigabe, Flow (OIDC/SAML/Passkey); __Host- kommt weiter davor")

# (c)
c = TinySesam(_cfg(cookie_prefix="meineapp_", session_cookie="eigen_sitzung"))
assert c.session_cookie_name == "eigen_sitzung" and c.flow_cookie_name("__Host-tinysesam_link") == "__Host-tinysesam_link"
ok("ausdrücklich gesetzter Name und __-Namen (Gateway-Cookies) bleiben")


# (d)
def _ablauf(praefix):
    auth, app = _oidc_app(**({"cookie_prefix": praefix} if praefix else {}))
    start = TestClient(app).get("/auth/oidc/start", follow_redirects=False)
    assert start.status_code in (302, 303), start.status_code
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    kopf = "; ".join(f"{n}={v}" for n, v in start.cookies.items())
    rueck = TestClient(app).get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False,
                                headers={"Cookie": _durch_proxy(kopf)})
    return kopf, rueck, auth


kopf, rueck, auth = _ablauf("meineapp_")
assert "meineapp_oidc_flow=" in kopf, kopf
assert rueck.status_code in (302, 303) and auth.session_cookie_name in rueck.headers.get("set-cookie", ""), (
    rueck.status_code, rueck.text[:200])
ok("mit Präfix: Flow-Cookie übersteht den Proxy, Rückweg meldet an (Sitzungs-Cookie meineapp_session)")
kopf, rueck, _ = _ablauf(None)
assert "tinysesam_oidc_flow=" in kopf and _durch_proxy(kopf) == ""
assert rueck.status_code == 400 and "set-cookie" not in {k.lower() for k in rueck.headers if "session" in rueck.headers[k]}, rueck.status_code
ok("Gegenprobe ohne Präfix: der Proxy entfernt das Flow-Cookie, Rückweg 400 (der Fehler aus dem Betrieb)")

# (e)
for boese in ("", "__Host-x_", "a b", "x" * 40, "-x"):
    f, _ = pruefe(_cfg(cookie_prefix=boese))
    assert any("cookie_prefix" in z for z in f), (boese, f)
f, _ = pruefe(_cfg(cookie_prefix="meineapp_"))
assert not any("cookie_prefix" in z for z in f), f
f, _ = pruefe(_cfg(cookie_prefix="meineapp_", forward_auth_enabled=True, trusted_redirect_hosts=["app.example.com"]))
assert any("cookie_prefix" in z and "forward_auth_enabled" in z for z in f), f
f, _ = pruefe(_cfg(cookie_prefix="tinysesam_zwei_", forward_auth_enabled=True, trusted_redirect_hosts=["app.example.com"]))
assert not any("cookie_prefix" in z for z in f), f
ok("Konfigprüfung: kaputtes Präfix und Gateway mit fremdem Präfix → Fehler; gültige Fälle frei")

print("cookie_prefix OK")

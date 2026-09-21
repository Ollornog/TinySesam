"""OIDC: Der JWKS muss eine Schlüsselrotation beim Provider überleben.

Bis 0.18.0 wurde das Schlüssel-Set **einmal** geholt und für die Lebensdauer des Prozesses
behalten. Provider rotieren ihre Signaturschlüssel aber regelmässig (Keycloak, Entra, Auth0).
Nach einer Rotation nennt jedes frische ID-Token eine `kid`, die das gecachte Set nicht kennt —
und damit scheiterte JEDER Login an der Signatur, bis jemand den Dienst neu startete. Ein
Ausfall, der niemandem als Konfigurationsfehler erkennbar war.

Diese Suite fährt ohne Netz: Discovery, Token-Endpunkt und JWKS sind Attrappen.
"""
from __future__ import annotations

import sys
import time
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from voraussetzung import braucht_modul  # noqa: E402

braucht_modul("authlib", extra="oidc")
braucht_modul("httpx")

from tinysesam.oidc import OIDCClient  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("OIDC — JWKS und Schlüsselrotation")

META = {"issuer": "https://id.example.com", "jwks_uri": "https://id.example.com/jwks",
        "token_endpoint": "https://id.example.com/token",
        "authorization_endpoint": "https://id.example.com/auth"}


def frischer_client():
    c = OIDCClient("https://id.example.com", "cid", "geheim", "openid")
    c._meta, c._meta_zeit = dict(META), time.time()
    return c


# ---------- 1) Das Set wird gecacht, altert aber ----------
abrufe = []


def zaehlende_holung(c):
    """`_jwkset` mit einem Zähler unterlegen, ohne die Cache-Logik nachzubauen."""
    modul = sys.modules["tinysesam.oidc"]

    class FakeJWK:
        @staticmethod
        def import_key_set(daten):
            return f"set-{daten['nr']}"

    class FakeAntwort:
        def __init__(self, nr):
            self._nr = nr

        def json(self):
            return {"nr": self._nr}

    def fake_get(url, **kw):
        abrufe.append(url)
        return FakeAntwort(len(abrufe))

    fake_httpx = types.SimpleNamespace(get=fake_get)
    fake_jose = types.SimpleNamespace(JsonWebKey=FakeJWK)
    sys.modules["httpx"] = fake_httpx
    sys.modules["authlib.jose"] = fake_jose
    return modul


c = frischer_client()
echtes_httpx = sys.modules.get("httpx")
echtes_jose = sys.modules.get("authlib.jose")
zaehlende_holung(c)
try:
    erstes = c._jwkset()
    zweites = c._jwkset()
    r.check("das Set wird gecacht (ein Abruf für zwei Aufrufe)",
            erstes == zweites and len(abrufe) == 1, f"{len(abrufe)} Abrufe")

    drittes = c._jwkset(erzwingen=True)
    r.check("ein erzwungener Abruf holt neu", drittes != erstes and len(abrufe) == 2,
            f"{len(abrufe)} Abrufe, Ergebnis {drittes!r}")

    c._jwks_zeit -= c.JWKS_TTL + 1
    viertes = c._jwkset()
    r.check("nach Ablauf der Lebensdauer wird von selbst neu geholt",
            viertes != drittes and len(abrufe) == 3, f"{len(abrufe)} Abrufe")
finally:
    if echtes_httpx is not None:
        sys.modules["httpx"] = echtes_httpx
    if echtes_jose is not None:
        sys.modules["authlib.jose"] = echtes_jose
    else:
        sys.modules.pop("authlib.jose", None)

# ---------- 2) Die Drossel gegen Fremdlast ----------
c2 = frischer_client()
c2._jwks, c2._jwks_zeit = "irgendwas", time.time()
r.check("direkt nach einem Abruf ist die Auffrischung gesperrt", not c2._jwks_auffrischbar(),
        "jedes kaputte id_token könnte einen Abruf beim Provider auslösen")
c2._jwks_zeit -= c2.JWKS_MIN_ABSTAND + 1
r.check("nach dem Mindestabstand ist sie wieder erlaubt", c2._jwks_auffrischbar(),
        "die Drossel öffnet nie — dann hilft sie auch nicht bei einer Rotation")


# ---------- 3) Der eigentliche Fall: Rotation mitten im Betrieb ----------
# `exchange()` holt ein Token, verifiziert es gegen das Set, und soll bei einem
# Signaturfehler EINMAL neu holen und erneut versuchen.
class FakeClaims(dict):
    def validate(self):
        pass


def baue_exchange_umgebung(c, versuche):
    """httpx.post liefert ein id_token; jwt.decode scheitert beim ersten Set und klappt beim zweiten."""
    modul = sys.modules["tinysesam.oidc"]

    class FakeAntwort:
        def json(self):
            return {"id_token": "tok", "access_token": "at"}

    class FakeJWK:
        @staticmethod
        def import_key_set(daten):
            return daten["set"]

    zustand = {"aktuelles_set": "alt"}

    def fake_get(url, **kw):
        class A:
            @staticmethod
            def json():
                return {"set": zustand["aktuelles_set"]}
        return A()

    def fake_decode(token, schluessel, claims_options=None):
        versuche.append(schluessel)
        if schluessel != "neu":
            raise ValueError("bad signature: unknown kid")
        return FakeClaims({"sub": "u1", "nonce": None})

    sys.modules["httpx"] = types.SimpleNamespace(post=lambda *a, **k: FakeAntwort(), get=fake_get)
    sys.modules["authlib.jose"] = types.SimpleNamespace(JsonWebKey=FakeJWK, jwt=types.SimpleNamespace(decode=fake_decode))
    return zustand


c3 = frischer_client()
versuche = []
echtes_httpx = sys.modules.get("httpx")
echtes_jose = sys.modules.get("authlib.jose")
zustand = baue_exchange_umgebung(c3, versuche)
try:
    c3._jwks, c3._jwks_zeit = "alt", time.time() - c3.JWKS_MIN_ABSTAND - 1
    zustand["aktuelles_set"] = "neu"          # der Provider hat rotiert
    claims, tok = c3.exchange("code", "https://app.example.com/cb", None)
    r.check("nach einer Schlüsselrotation klappt der Login im zweiten Anlauf",
            claims.get("sub") == "u1", f"claims={dict(claims) if claims else None}")
    r.check("und zwar durch genau EINEN Neu-Abruf, nicht durch Raten",
            versuche == ["alt", "neu"], f"Versuche: {versuche}")

    # Die Drossel darf den Notausgang schliessen: frisch geholt → kein zweiter Anlauf.
    c4 = frischer_client()
    versuche2 = []
    baue_exchange_umgebung(c4, versuche2)
    c4._jwks, c4._jwks_zeit = "alt", time.time()      # gerade eben geholt
    try:
        c4.exchange("code", "https://app.example.com/cb", None)
        durchgerutscht = True
    except Exception:
        durchgerutscht = False
    r.check("ein Strom kaputter Tokens löst keinen Abruf-Sturm aus",
            not durchgerutscht and versuche2 == ["alt"],
            f"Versuche: {versuche2} — die Drossel greift nicht")
finally:
    if echtes_httpx is not None:
        sys.modules["httpx"] = echtes_httpx
    if echtes_jose is not None:
        sys.modules["authlib.jose"] = echtes_jose
    else:
        sys.modules.pop("authlib.jose", None)

sys.exit(r.done())

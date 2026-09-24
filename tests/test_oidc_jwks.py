"""OIDC: Der JWKS muss eine Schlüsselrotation beim Provider überleben.

Bis 0.18.0 wurde das Schlüssel-Set **einmal** geholt und für die Lebensdauer des Prozesses
behalten. Provider rotieren ihre Signaturschlüssel aber regelmässig (Keycloak, Entra, Auth0).
Nach einer Rotation nennt jedes frische ID-Token eine `kid`, die das gecachte Set nicht kennt —
und damit scheiterte JEDER Login an der Signatur, bis jemand den Dienst neu startete. Ein
Ausfall, der niemandem als Konfigurationsfehler erkennbar war.

Diese Suite fährt ohne Netz: Discovery, Token-Endpunkt und JWKS sind Attrappen.
"""
from __future__ import annotations

import re
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
    def validate(self, *a, **k):
        pass


def baue_exchange_umgebung(c, versuche):
    """httpx.post liefert ein id_token; jwt.decode scheitert beim ersten Set und klappt beim zweiten."""

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
        # `aud` gehört dazu, seit `exchange()` das Publikum prüft (F-15): Ein Token ohne
        # passendes `aud` ist keines für uns, und die Attrappe soll ein gültiges nachstellen.
        return FakeClaims({"sub": "u1", "nonce": None, "aud": c.client_id})

    sys.modules["httpx"] = types.SimpleNamespace(post=lambda *a, **k: FakeAntwort(), get=fake_get)
    # `exchange` baut sich den Dekoder selbst (mit fester Algorithmenliste, s. Abschnitt 4) —
    # die Attrappe muss ihn nachbilden, sonst prüft dieser Abschnitt einen Importfehler.
    fake_jwt = types.SimpleNamespace(decode=fake_decode)
    sys.modules["authlib.jose"] = types.SimpleNamespace(
        JsonWebKey=FakeJWK, JsonWebToken=lambda algs: fake_jwt, jwt=fake_jwt)
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

# ---------- 4) Algorithmen-Konfusion: das Token bestimmt nicht, wie es geprüft wird ----------
# `authlib.jose.jwt` ist ein Dekoder MIT Vorgabesatz, und der enthält HS256. Wird beim Dekodieren
# kein Verfahren genannt, entscheidet der **Header des Tokens**, wie geprüft wird — also der
# Absender. Bis authlib 1.3.0 liess sich damit ein ID-Token mit dem öffentlichen Schlüssel als
# HMAC-Geheimnis fälschen (GHSA-5357-c2jx-v7qh); der Boden in `pyproject.toml` lag bei 1.3, eine
# Installation mit Lockfile bekam genau diese Fassung. Der dauerhafte Riegel ist nicht die
# Version, sondern die eigene Liste: `OIDCClient.ID_TOKEN_ALGS` (B4-1 aus T-13).
import base64  # noqa: E402
import hashlib  # noqa: E402
import hmac  # noqa: E402
import json  # noqa: E402

from authlib.jose import JsonWebKey as _JWK  # noqa: E402
from authlib.jose import jwt as _vorgabe_dekoder  # noqa: E402
from tinysesam import errors as _err4  # noqa: E402

r.check("die Liste nennt kein symmetrisches Verfahren und kein 'none'",
        all(a.startswith(("RS", "PS", "ES", "Ed")) for a in OIDCClient.ID_TOKEN_ALGS),
        f"ID_TOKEN_ALGS={OIDCClient.ID_TOKEN_ALGS}")

c6 = frischer_client()
try:
    c6.ID_TOKEN_ALGS = ("RS256", "HS256")
    c6._dekoder()
    gewacht = False
except _err4.ConfigError:
    gewacht = True
r.check("HS256 in der Liste wird abgewiesen, nicht durchgereicht", gewacht,
        "eine spätere Erweiterung könnte das Loch wieder aufreissen")


def _b64(rohdaten: bytes) -> bytes:
    return base64.urlsafe_b64encode(rohdaten).rstrip(b"=")


def _hs256(geheimnis: bytes, nutzlast: dict, kid: str = "k1") -> str:
    """Ein HS256-Token bauen — das, was der Angreifer schickt."""
    kopf = _b64(json.dumps({"alg": "HS256", "kid": kid, "typ": "JWT"}, separators=(",", ":")).encode())
    rumpf = _b64(json.dumps(nutzlast, separators=(",", ":")).encode())
    sig = _b64(hmac.new(geheimnis, kopf + b"." + rumpf, hashlib.sha256).digest())
    return (kopf + b"." + rumpf + b"." + sig).decode()


def _oidc_umgebung(jwks_dokument, id_token):
    """httpx-Attrappe: der Token-Endpunkt liefert `id_token`, der JWKS-Endpunkt das Set."""
    class Antwort:
        def __init__(self, nutzlast):
            self._n = nutzlast

        def json(self):
            return self._n

    sys.modules["httpx"] = types.SimpleNamespace(
        post=lambda *a, **k: Antwort({"id_token": id_token, "access_token": "at"}),
        get=lambda *a, **k: Antwort(jwks_dokument))


privat = _JWK.generate_key("RSA", 2048, {"kid": "k1"}, is_private=True)
JWKS_RSA = {"keys": [privat.as_dict(is_private=False)]}
NUTZLAST = {"iss": META["issuer"], "aud": "cid", "sub": "u1", "nonce": "n1",
            "iat": int(time.time()), "exp": int(time.time()) + 600}
OPTIONEN = {"iss": {"essential": True, "value": META["issuer"]},
            "aud": {"essential": True, "value": "cid"}}

echtes_httpx4 = sys.modules.get("httpx")
try:
    # a) Der legitime Weg bleibt offen: ein echtes RS256-Token geht durch `exchange`.
    echt = _vorgabe_dekoder.encode({"alg": "RS256", "kid": "k1"}, dict(NUTZLAST), privat).decode()
    c7 = frischer_client()
    _oidc_umgebung(JWKS_RSA, echt)
    claims, _tok = c7.exchange("code", "https://app.example.com/cb", "n1")
    r.check("der legitime Weg bleibt offen: RS256 gegen das JWKS wird angenommen",
            claims.get("sub") == "u1", f"claims={dict(claims) if claims else None}")

    # b) Der Angriff: gleiches JWKS, aber `alg: HS256` mit dem öffentlichen Schlüssel als
    #    HMAC-Geheimnis. Der Angreifer kennt das JWKS — es ist öffentlich abrufbar.
    oeffentlich = json.dumps(privat.as_dict(is_private=False), separators=(",", ":")).encode()
    gefaelscht = _hs256(oeffentlich, {**NUTZLAST, "sub": "angreifer"})
    c8 = frischer_client()
    _oidc_umgebung(JWKS_RSA, gefaelscht)
    try:
        c8.exchange("code", "https://app.example.com/cb", "n1")
        durch = True
    except Exception:
        durch = False
    r.check("ein HS256-Token gegen das RSA-JWKS wird abgewiesen", not durch,
            "der öffentliche Schlüssel wäre damit das Signaturgeheimnis")

    # c) Vorbedingung — und zugleich der Beweis, dass die Liste WIRKT und nicht nur dasteht:
    #    Derselbe Angriff gegen einen Schlüsselsatz, in dem authlibs Vorgabe-Dekoder HMAC
    #    tatsächlich ausführt. Die Vorgabe nimmt das Token an, der Dekoder von TinySesam nicht.
    #    Ohne die feste Liste in `_dekoder()` wären beide Zeilen gleich — und dieser Test rot.
    geheim = b"0123456789abcdef0123456789abcdef"
    jwks_oct = {"keys": [{"kty": "oct", "kid": "k1", "k": _b64(geheim).decode()}]}
    tok_oct = _hs256(geheim, {**NUTZLAST, "sub": "angreifer"})
    satz = _JWK.import_key_set(jwks_oct)
    try:
        vorgabe = _vorgabe_dekoder.decode(tok_oct, satz, claims_options=OPTIONEN)
        vorgabe.validate()
        vorgabe_nahm_an = vorgabe.get("sub") == "angreifer"
    except Exception:
        vorgabe_nahm_an = False
    r.check("Vorbedingung: authlibs Vorgabe-Dekoder nimmt genau dieses HS256-Token an",
            vorgabe_nahm_an,
            "ohne diese Vorbedingung misst der nächste Test nichts — dann läge es an authlib")

    c9 = frischer_client()
    try:
        c9._dekoder().decode(tok_oct, satz, claims_options=OPTIONEN)
        eigener_nahm_an = True
    except Exception:
        eigener_nahm_an = False
    r.check("der Dekoder von TinySesam lehnt dasselbe Token ab", not eigener_nahm_an,
            "die Algorithmenliste greift nicht — `alg` im Header entscheidet wieder")
finally:
    if echtes_httpx4 is not None:
        sys.modules["httpx"] = echtes_httpx4
    else:
        sys.modules.pop("httpx", None)


# ---------- 5) Discovery: Issuer-Vergleich, keine Umleitung ----------
# Aus dem Discovery-Dokument kommen token_endpoint, jwks_uri und der Issuer, gegen den jedes
# ID-Token geprüft wird. Bis 0.18.0 wurde es mit follow_redirects=True geholt und nie mit
# oidc_issuer verglichen: Ein 3xx auf dem Well-Known-Pfad hätte den ganzen Login ersetzt (RB-03).
from tinysesam import errors as _errors  # noqa: E402


def discovery_client(status, dokument):
    aufrufe = []

    class Antwort:
        status_code = status

        @staticmethod
        def json():
            return dokument

    def fake_get(url, **kw):
        aufrufe.append((url, kw))
        return Antwort()

    sys.modules["httpx"] = types.SimpleNamespace(get=fake_get)
    return OIDCClient("https://id.example.com", "cid", "geheim", "openid"), aufrufe


def meta_fehler(c):
    try:
        c.meta()
    except _errors.ConfigError as e:
        return str(e)
    return None


echtes_httpx5 = sys.modules.get("httpx")
try:
    c5, auf = discovery_client(200, dict(META))
    r.check("passendes Dokument wird angenommen", meta_fehler(c5) is None and c5.meta()["issuer"] == META["issuer"])
    r.check("Discovery wird OHNE Umleitung abgerufen",
            auf and auf[0][1].get("follow_redirects") is False, f"Aufruf: {auf}")

    c5b, _ = discovery_client(200, {**META, "issuer": "https://id.example.com/"})
    r.check("Schrägstrich am Ende des issuer zählt nicht als Abweichung", meta_fehler(c5b) is None)

    c5c, _ = discovery_client(200, {**META, "issuer": "https://attacker.example"})
    f = meta_fehler(c5c)
    r.check("fremder issuer im Dokument → ConfigError, beide Werte in der Meldung",
            f is not None and re.search(r"attacker\.example", f) and re.search(r"oidc_issuer=https://id\.example\.com\b", f),
            f"Fehler: {f}")

    c5d, _ = discovery_client(302, {})
    f = meta_fehler(c5d)
    r.check("302 auf dem Well-Known-Pfad wird nicht gefolgt, sondern abgewiesen",
            f is not None and "302" in f, f"Fehler: {f}")

    # Vorbedingung, damit die Prüfung oben nicht aus Versehen grün ist: Ohne den Vergleich
    # ginge das fremde Dokument durch — genau das war der Befund.
    c5e, _ = discovery_client(200, {**META, "issuer": "https://attacker.example"})
    c5e._pruefe_issuer = lambda meta: None
    r.check("Vorbedingung: ohne den Vergleich ginge das fremde Dokument durch", meta_fehler(c5e) is None)
finally:
    if echtes_httpx5 is not None:
        sys.modules["httpx"] = echtes_httpx5
    else:
        sys.modules.pop("httpx", None)

# ---------- 6) T-14: ein Provider, mehrere Clients ----------
# Discovery-Dokument und JWKS hängen am Provider, nicht am Client. Würde jeder Client einzeln
# fragen, holte eine Installation mit drei Anwendungen dasselbe Dokument dreifach — und eine
# Schlüsselrotation wäre dreimal zu bemerken statt einmal. Der Flow-Teil (welcher Client für
# welchen Host) steht in tests/test_forward_auth.py, wo der TestClient zu Hause ist.
from tinysesam import TinySesamConfig                                    # noqa: E402
from tinysesam.oidc import OIDCClients, VORGABE_CLIENT                   # noqa: E402

_cfg14 = TinySesamConfig(
    db_path="/dev/null", passkey_enabled=False,
    oidc_enabled=True, oidc_issuer="https://id.example.com",
    oidc_client_id="haupt", oidc_client_secret="s-haupt",
    oidc_clients={"app-a.example.com": {"client_id": "a", "client_secret": "s-a"},
                  "app-b.example.com": {"client_id": "b", "client_secret": "s-b",
                                        "scopes": "openid profile email groups"}})
_reg = OIDCClients(_cfg14)
_reg[VORGABE_CLIENT]._meta, _reg[VORGABE_CLIENT]._meta_zeit = dict(META), time.time()
_reg._teile_meta()

r.check("jede Anwendung hat ihren eigenen Client beim selben Provider",
        [_reg.fuer_host(h).client_id for h in ("app-a.example.com", "app-b.example.com")] == ["a", "b"])
r.check("ein unbekannter Host bekommt den Vorgabe-Client, der Flow bricht nicht ab",
        _reg.fuer_host("fremd.example.com").client_id == "haupt")
r.check("der Port gehört nicht zum Namen der Anwendung",
        _reg.fuer_host("app-b.example.com:8443").client_id == "b")
r.check("ein eigener Scope je Anwendung wird übernommen",
        "groups" in _reg["app-b.example.com"].scopes
        and _reg["app-a.example.com"].scopes == _cfg14.oidc_scopes)
r.check("alle Clients teilen die Metadaten des einen Providers",
        all(_reg[k]._meta is _reg[VORGABE_CLIENT]._meta for k in _reg.namen()))
r.check("und denselben Issuer — ein zweiter Provider ist nicht vorgesehen",
        {_reg[k].issuer for k in _reg.namen()} == {"https://id.example.com"})

# ---------- 7) F-15: aud und azp nach OIDC Core 3.1.3.7 ----------
# Der Dekoder prüft nur, dass die eigene client_id in `aud` VORKOMMT. Ein Token darf mehrere
# Empfänger nennen — dann sagt erst `azp`, für wen es gemacht wurde. Ohne diese Prüfung nimmt
# TinySesam ein Token an, das für eine ANDERE Anwendung desselben Providers ausgestellt wurde
# und uns nur mitnennt (Token-Substitution). Seit T-14 wiegt das doppelt: Bei mehreren Clients
# derselben Installation wäre das Token von App A auch an App B gut.
from fastapi import HTTPException as _HTTPException                      # noqa: E402

_c15 = frischer_client()


def _publikum_fehler(**claims):
    try:
        _c15._pruefe_publikum(FakeClaims(claims), lambda k, **f: k)
        return None
    except _HTTPException as e:
        return e.detail


r.check("ein Token nur für uns geht durch", _publikum_fehler(aud="cid") is None)
r.check("mehrere Empfänger MIT passendem azp gehen durch",
        _publikum_fehler(aud=["cid", "andere"], azp="cid") is None)
r.check("mehrere Empfänger OHNE azp werden abgewiesen",
        _publikum_fehler(aud=["cid", "andere"]) == "api.oidc_audience")
r.check("ein fremdes azp wird abgewiesen, auch wenn wir in aud stehen",
        _publikum_fehler(aud=["cid", "andere"], azp="andere") == "api.oidc_audience")
r.check("ein Token ganz ohne uns wird abgewiesen",
        _publikum_fehler(aud=["andere"]) == "api.oidc_audience")
r.check("ein Token ohne aud wird abgewiesen", _publikum_fehler() == "api.oidc_audience")
r.check("ein einzelnes fremdes azp allein genügt zur Abweisung",
        _publikum_fehler(aud="cid", azp="andere") == "api.oidc_audience")

# ---------- 8) F-18: die UserInfo-Antwort muss zum ID-Token passen ----------
# Die Antwort ist NICHT signiert und wird im Callback über die Claims gelegt — sie liefert
# Gruppen, E-Mail und damit mittelbar Rollen und das Admin-Flag. OIDC Core 5.3.2 verlangt den
# Abgleich des `sub` ausdrücklich.
_c18 = frischer_client()
_echtes_httpx18 = sys.modules.get("httpx")


def _userinfo_mit(antwort, erwartet):
    class A:
        @staticmethod
        def json():
            return antwort
    sys.modules["httpx"] = types.SimpleNamespace(get=lambda *a, **k: A())
    try:
        return _c18.userinfo("at", erwartetes_sub=erwartet)
    finally:
        if _echtes_httpx18 is not None:
            sys.modules["httpx"] = _echtes_httpx18
        else:
            sys.modules.pop("httpx", None)


_c18._meta = {**META, "userinfo_endpoint": "https://id.example.com/userinfo"}
_c18._meta_zeit = time.time()
r.check("passendes sub → die Antwort wird verwertet",
        _userinfo_mit({"sub": "u1", "groups": ["a"]}, "u1").get("groups") == ["a"])
r.check("fremdes sub → die Antwort wird verworfen, nicht teilweise übernommen",
        _userinfo_mit({"sub": "u2", "groups": ["admins"], "email": "wer@example.com"}, "u1") == {})
r.check("Antwort ohne sub → verworfen (fail-closed statt teilweise übernehmen)",
        _userinfo_mit({"groups": ["admins"]}, "u1") == {})
r.check("ohne erwartetes sub bekommt der Aufrufer nichts",
        _userinfo_mit({"sub": "u1", "groups": ["a"]}, "") == {})
r.check("eine Antwort, die kein Objekt ist, wird verworfen",
        _userinfo_mit(["kein", "objekt"], "u1") == {})

# ---------- 9) F-20/H-12: PKCE mit S256 ----------
# Ohne PKCE war ein abgefangener Autorisierungs-Code (Referer, Proxy-Log, Browser-Verlauf)
# einlösbar, solange der Angreifer auch das Client-Secret hat — oder in einen fremden Flow
# injizierbar. Der Verifier bleibt im Flow-Satz; nur die Challenge reist durch den Browser.
from urllib.parse import parse_qs as _pqs, urlparse as _up  # noqa: E402
from tinysesam.oidc import pkce_paar  # noqa: E402

_v, _ch = pkce_paar()
_erwartet = base64.urlsafe_b64encode(hashlib.sha256(_v.encode()).digest()).rstrip(b"=").decode()
r.check("pkce_paar: Challenge = BASE64URL(SHA256(Verifier)) ohne Auffüllung (RFC 7636 4.2)",
        _ch == _erwartet and "=" not in _ch, f"{_ch} ≠ {_erwartet}")
r.check("pkce_paar: Verifier 43–128 Zeichen aus dem erlaubten Alphabet",
        43 <= len(_v) <= 128 and re.fullmatch(r"[A-Za-z0-9\-._~]+", _v) is not None, _v)
r.check("pkce_paar: jeder Aufruf ein neues Paar", pkce_paar()[0] != _v)
_q = _pqs(_up(frischer_client().auth_url("https://app.example.com/cb", "st", "no",
                                         code_challenge=_ch)).query)
r.check("auth_url trägt code_challenge und code_challenge_method=S256",
        _q.get("code_challenge") == [_ch] and _q.get("code_challenge_method") == ["S256"], _q)

_posts = []


def _pkce_umgebung(id_token):
    class A:
        def __init__(self, n):
            self._n = n

        def json(self):
            return self._n

    def _post(url, **kw):
        _posts.append(kw.get("data") or {})
        return A({"id_token": id_token, "access_token": "at"})

    sys.modules["httpx"] = types.SimpleNamespace(post=_post, get=lambda *a, **k: A(JWKS_RSA))


echtes_httpx9 = sys.modules.get("httpx")
try:
    _tok9 = _vorgabe_dekoder.encode({"alg": "RS256", "kid": "k1"}, dict(NUTZLAST), privat).decode()
    _pkce_umgebung(_tok9)
    frischer_client().exchange("code", "https://app.example.com/cb", "n1", code_verifier=_v)
    r.check("exchange schickt den code_verifier an den Token-Endpunkt",
            _posts and _posts[-1].get("code_verifier") == _v, _posts)

    # ---------- 10) F-25: ein ID-Token ohne `exp` gilt nicht für immer ----------
    def _tausch(nutzlast):
        tok = _vorgabe_dekoder.encode({"alg": "RS256", "kid": "k1"}, nutzlast, privat).decode()
        _pkce_umgebung(tok)
        try:
            frischer_client().exchange("code", "https://app.example.com/cb", "n1")
            return None
        except Exception as e:           # noqa: BLE001 — jede Abweisung zählt hier als Nein
            return type(e).__name__

    _ohne_exp = {k: v for k, v in NUTZLAST.items() if k != "exp"}
    r.check("F-25: ein ID-Token OHNE exp wird abgewiesen", _tausch(_ohne_exp) is not None,
            "authlib prüft exp nur, wenn der Claim da ist — das Token gälte für immer")
    r.check("F-25: Gegenprobe — mit exp geht dasselbe Token durch", _tausch(dict(NUTZLAST)) is None)

    # ---------- 11) F-26: ein paar Sekunden Uhrvorlauf beim Provider blockieren keinen Login ----------
    _t = int(time.time())
    r.check("F-26: iat 30 s in der Zukunft (Provider-Uhr geht vor) wird angenommen",
            _tausch({**NUTZLAST, "iat": _t + 30, "nbf": _t + 30}) is None,
            "ohne leeway scheitert jeder Login, sobald die Uhr des IdP vorgeht")
    r.check("F-26: …aber die Toleranz ist begrenzt: iat weit in der Zukunft bleibt abgewiesen",
            _tausch({**NUTZLAST, "iat": _t + 3600, "nbf": _t + 3600}) is not None)
    r.check("F-26: ein abgelaufenes Token (exp jenseits der Toleranz) bleibt abgewiesen",
            _tausch({**NUTZLAST, "iat": _t - 600, "exp": _t - OIDCClient.UHR_TOLERANZ - 30}) is not None)
finally:
    if echtes_httpx9 is not None:
        sys.modules["httpx"] = echtes_httpx9
    else:
        sys.modules.pop("httpx", None)

# ---------- 12) F-24: eine Fehlerantwort des Providers wird nicht zwischengespeichert ----------
# Discovery: seit F-13 (#55) wirft ein Nicht-200 bzw. ein fremder Issuer, BEVOR `_meta` gesetzt
# wird. Gemessen wird hier, dass danach wirklich neu gefragt wird — sonst wäre ein Wartungsfenster
# des Providers 24 Stunden lang ein Ausfall hier.
echtes_httpx12 = sys.modules.get("httpx")
try:
    _folge = [(503, {"error": "wartung"}), (200, {"error": "server_error"}), (200, dict(META))]
    _abrufe12 = []

    def _get12(url, **kw):
        status, dok = _folge[min(len(_abrufe12), len(_folge) - 1)]
        _abrufe12.append(url)
        return types.SimpleNamespace(status_code=status, json=lambda d=dok: d)

    sys.modules["httpx"] = types.SimpleNamespace(get=_get12)
    c12 = OIDCClient("https://id.example.com", "cid", "geheim", "openid")
    _f1, _f2 = meta_fehler(c12), meta_fehler(c12)
    r.check("F-24: 503 und eine 200 mit Fehlerdokument werden abgewiesen und NICHT gemerkt",
            _f1 is not None and _f2 is not None and c12._meta is None and len(_abrufe12) == 2,
            f"_meta={c12._meta!r}, Abrufe={len(_abrufe12)}")
    r.check("F-24: der nächste Abruf nach Ende der Störung holt das echte Dokument",
            meta_fehler(c12) is None and c12.meta()["issuer"] == META["issuer"] and len(_abrufe12) == 3)

    # JWKS: eine Fehlerantwort (hier 500 mit leerem Satz) kommt nicht in den Cache.
    _jwks_folge = [(500, {"keys": []}), (200, JWKS_RSA)]
    _jwks_abrufe = []

    def _get12b(url, **kw):
        status, dok = _jwks_folge[min(len(_jwks_abrufe), 1)]
        _jwks_abrufe.append(url)
        return types.SimpleNamespace(status_code=status, json=lambda d=dok: d)

    sys.modules["httpx"] = types.SimpleNamespace(get=_get12b)
    c12b = frischer_client()
    try:
        c12b._jwkset()
        _jwks_fehler = None
    except _errors.ConfigError as e:
        _jwks_fehler = str(e)
    r.check("F-24: JWKS mit 500 wird abgewiesen und nicht gemerkt",
            _jwks_fehler is not None and "500" in _jwks_fehler and c12b._jwks is None,
            f"Fehler={_jwks_fehler!r}, Cache={c12b._jwks!r}")
    r.check("F-24: …der nächste Abruf holt den echten Satz", c12b._jwkset() is not None
            and len(_jwks_abrufe) == 2)
finally:
    if echtes_httpx12 is not None:
        sys.modules["httpx"] = echtes_httpx12
    else:
        sys.modules.pop("httpx", None)

sys.exit(r.done())

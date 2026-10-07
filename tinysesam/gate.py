"""Gate-Token: der Proxy prüft selbst, TinySesam nur beim Ausstellen (ADR-9, T-19).

Vor einer fremden Anwendung fragte der Proxy bis hierhin für JEDE Anfrage `/auth/forward` —
auch für jedes Skript, jedes Stylesheet, jedes Icon. Jetzt legt eine erfolgreiche Prüfung
zusätzlich ein kurzlebiges, signiertes Token in ein Cookie auf dem Host der Anwendung. Der
Proxy prüft dessen Signatur selbst (Caddy mit dem Plugin `caddy-jwt`) und fragt TinySesam erst
wieder, wenn es fehlt oder abgelaufen ist. Das Token ist damit das zwischengespeicherte
Ergebnis von `/auth/forward`, nicht mehr.

Die Bausteine, bewusst klein und ohne eigene Abhängigkeit (`cryptography` ist Pflicht):

* **Ed25519 (`EdDSA`)**, kein HMAC: Der Proxy bekommt nur den öffentlichen Schlüssel. Mit einem
  geteilten HMAC-Geheimnis könnte jeder, der die Proxy-Konfiguration liest, Token für jedes Konto
  ausstellen. `caddy-jwt` erzwingt den Algorithmus, wenn `sign_alg EdDSA` gesetzt ist — ein
  Token mit `alg: none` oder `HS256` im Kopf wird damit nicht anders geprüft.
* **Der Schlüssel wird abgeleitet**, nicht eigens verwaltet: HKDF-SHA256 aus dem Schlüssel, der
  schon die TOTP-Geheimnisse schützt (`geheimnis.schluessel_laden`). Damit gibt es kein zweites
  Geheimnis, das gesichert, verteilt und vergessen werden kann, und alle Worker derselben
  Installation signieren mit demselben Schlüssel. Wer den Grundschlüssel wechselt, wechselt auch
  diesen — der Proxy braucht dann den neuen öffentlichen Schlüssel (`tinysesam gate-key`).
* **`aud` trägt den Host UND die verlangten Rollen.** Ein Token, das für eine Prüfung ohne
  Rollenangabe ausgestellt wurde, darf an einem Pfad, der `?roles=admin` verlangt, nicht
  gelten — der Proxy sieht keine Rollen, nur die Zielgruppe. Deshalb steht die Rollenangabe in
  der Zielgruppe selbst (`zielgruppe()`), und der Proxy nennt dort genau diese Zeichenkette.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Optional

#: Fester Kontext der Ableitung. Eine neue Fassung bekäme einen neuen Wert — und damit einen
#: neuen Schlüssel, ohne dass der Grundschlüssel wechseln muss.
_HKDF_INFO = b"tinysesam gate-token v1"

#: Die Grenzen der Laufzeit. Darunter fragt der Proxy fast so oft wie ohne Token, darüber wird
#: aus „Widerruf greift nach Ablauf" ein Widerruf, der zu spät kommt (ADR-9, Konsequenzen).
TTL_MIN, TTL_MAX = 30, 3600

#: Präfix der Claims, die TinySesam selbst setzt — damit sie mit keinem registrierten Claim
#: (RFC 7519) und keinem eines Fremdsystems zusammenfallen.
CLAIM_PRAEFIX = "ts_"


def _b64u(daten: bytes) -> str:
    return base64.urlsafe_b64encode(daten).rstrip(b"=").decode("ascii")


def _b64u_lesen(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def schluessel_ableiten(grundschluessel: bytes):
    """Den Ed25519-Signaturschlüssel aus dem Grundschlüssel der Installation ableiten."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    saat = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(grundschluessel)
    return Ed25519PrivateKey.from_private_bytes(saat)


def oeffentlich_roh(privat) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return privat.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def oeffentlich_b64(privat) -> str:
    """Der öffentliche Schlüssel so, wie `caddy-jwt` ihn bei `sign_alg EdDSA` erwartet:
    die 32 Rohbytes, Standard-Base64."""
    return base64.b64encode(oeffentlich_roh(privat)).decode("ascii")


def schluessel_id(oeffentlich: bytes) -> str:
    """Kurze Kennung des Schlüssels (`kid`). Der Proxy braucht sie nicht; sie sagt beim Lesen
    eines Tokens, mit welchem Schlüssel es entstand — nach einem Wechsel die erste Frage."""
    return hashlib.sha256(oeffentlich).hexdigest()[:16]


def zielgruppe(host: str, rollen_gruppen=()) -> str:
    """Die Zielgruppe (`aud`) eines Tokens: Host, bei verlangten Rollen samt deren Angabe.

    `rollen_gruppen` ist die Form aus `?roles=` bzw. `X-TinySesam-Roles`: eine Liste von Gruppen,
    innerhalb einer Gruppe genügt EINE Rolle, die Gruppen gelten zusammen. Die Darstellung ist
    kanonisch (sortiert, ohne Dubletten), damit dieselbe Anforderung immer dieselbe Zeichenkette
    ergibt — der Proxy vergleicht sie Zeichen für Zeichen:

        zielgruppe("app.example.com")                          → "app.example.com"
        zielgruppe("app.example.com", [["redaktion", "admin"]]) → "app.example.com|roles=admin,redaktion"
    """
    h = str(host or "").strip().lower().rstrip(".")
    gruppen = sorted({",".join(sorted({r for r in g if r})) for g in (rollen_gruppen or ()) if any(g)})
    return h + ("|roles=" + ";".join(gruppen) if gruppen else "")


def ausstellen(privat, *, iss: str, aud: str, sub: str, claims: dict, ttl: int, jetzt: int) -> str:
    """Ein signiertes Token (JWS Compact, `EdDSA`). `claims` sind die TinySesam-eigenen Felder
    ohne Präfix; sie landen als `ts_<name>`."""
    kopf = {"alg": "EdDSA", "typ": "JWT", "kid": schluessel_id(oeffentlich_roh(privat))}
    inhalt = {"iss": iss, "aud": aud, "sub": str(sub), "iat": int(jetzt), "nbf": int(jetzt),
              "exp": int(jetzt) + int(ttl), "jti": secrets.token_urlsafe(12)}
    for name, wert in claims.items():
        inhalt[CLAIM_PRAEFIX + name] = wert
    teile = (_b64u(json.dumps(kopf, separators=(",", ":")).encode()) + "."
             + _b64u(json.dumps(inhalt, separators=(",", ":"), ensure_ascii=False).encode("utf-8")))
    return teile + "." + _b64u(privat.sign(teile.encode("ascii")))


def pruefen(oeffentlich: bytes, token: str, *, aud: str, iss: str, jetzt: int) -> Optional[dict]:
    """Ein Token so prüfen, wie der Proxy es tut — für Tests und Diagnose. None bei jedem Fehler.

    Fail-closed: Algorithmus fest `EdDSA` (der Kopf wird nicht befragt, nur verglichen), Signatur,
    `iss`, `aud`, `nbf`, `exp`. Ohne Uhrenspielraum — den gibt der Proxy, wenn überhaupt."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        k, i, s = str(token or "").split(".")
        kopf = json.loads(_b64u_lesen(k))
        if kopf.get("alg") != "EdDSA":
            return None
        Ed25519PublicKey.from_public_bytes(oeffentlich).verify(_b64u_lesen(s), f"{k}.{i}".encode("ascii"))
        inhalt = json.loads(_b64u_lesen(i).decode("utf-8"))
    except (ValueError, TypeError, InvalidSignature, UnicodeDecodeError):
        return None
    if not isinstance(inhalt, dict) or inhalt.get("iss") != iss:
        return None
    zg = inhalt.get("aud")
    if not (zg == aud or (isinstance(zg, list) and aud in zg)):
        return None
    try:
        if int(inhalt["nbf"]) > jetzt or int(inhalt["exp"]) <= jetzt:
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return inhalt


def set_cookie(name: str, token: str, ttl: int) -> str:
    """Der Wert eines `Set-Cookie`-Headers für das Gate-Cookie.

    Immer `Secure` und `Path=/`, nie `Domain`: Das Präfix `__Host-` verlangt genau das, und der
    Browser verwirft ein `__Host-`-Cookie, dem eines davon fehlt. Ohne `Domain` gilt es nur für
    den Host, für den es ausgestellt wurde — ein Token für app-a erreicht app-b gar nicht erst.
    `HttpOnly`: Das Skript der fremden Anwendung hat es nicht zu lesen."""
    return f"{name}={token}; Path=/; Max-Age={int(ttl)}; Secure; HttpOnly; SameSite=Lax"

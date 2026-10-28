"""Gate token: the proxy checks by itself, TinySesam only at issuing (ADR-9, T-19).

In front of a foreign application the proxy used to ask `/auth/forward` for EVERY request —
even for every script, every stylesheet, every icon. Now a successful check
additionally puts a short-lived, signed token into a cookie on the application's host. The
proxy checks its signature itself (Caddy with the plugin `caddy-jwt`) and asks TinySesam again
only when it is missing or expired. The token is thus the cached
result of `/auth/forward`, nothing more.

The building blocks, deliberately small and without a dependency of their own (`cryptography` is mandatory):

* **Ed25519 (`EdDSA`)**, not HMAC: the proxy gets only the public key. With a
  shared HMAC secret anyone who reads the proxy configuration could issue tokens for any
  account. `caddy-jwt` enforces the algorithm when `sign_alg EdDSA` is set — a
  token with `alg: none` or `HS256` in its header is therefore not checked any differently.
* **The key is derived**, not managed separately: HKDF-SHA256 from the key that
  already protects the TOTP secrets (`geheimnis.schluessel_laden`). So there is no second
  secret that can be backed up, distributed and forgotten, and all workers of the same
  installation sign with the same key. Whoever changes the base key changes
  this one too — the proxy then needs the new public key (`tinysesam gate-key`).
* **`aud` carries the host AND the required roles.** A token issued for a check without
  role specification must not be valid on a path that requires `?roles=admin` —
  the proxy sees no roles, only the audience. That is why the role specification is in
  the audience itself (`zielgruppe()`), and the proxy names exactly this string there.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Optional

#: Fixed context of the derivation. A new version would get a new value — and thus a
#: new key, without the base key having to change.
_HKDF_INFO = b"tinysesam gate-token v1"

#: The limits of the lifetime. Below, the proxy asks almost as often as without a token; above,
#: "revocation takes effect after expiry" becomes a revocation that comes too late (ADR-9, consequences).
TTL_MIN, TTL_MAX = 30, 3600

#: Prefix of the claims TinySesam sets itself — so they collide with no registered claim
#: (RFC 7519) and none of a foreign system.
CLAIM_PRAEFIX = "ts_"


def _b64u(daten: bytes) -> str:
    return base64.urlsafe_b64encode(daten).rstrip(b"=").decode("ascii")


def _b64u_lesen(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def schluessel_ableiten(grundschluessel: bytes):
    """Derive the Ed25519 signing key from the installation's base key."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    saat = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(grundschluessel)
    return Ed25519PrivateKey.from_private_bytes(saat)


def oeffentlich_roh(privat) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return privat.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def oeffentlich_b64(privat) -> str:
    """The public key the way `caddy-jwt` expects it with `sign_alg EdDSA`:
    the 32 raw bytes, standard Base64."""
    return base64.b64encode(oeffentlich_roh(privat)).decode("ascii")


def schluessel_id(oeffentlich: bytes) -> str:
    """Short identifier of the key (`kid`). The proxy does not need it; when reading
    a token it says which key produced it — the first question after a rotation."""
    return hashlib.sha256(oeffentlich).hexdigest()[:16]


def zielgruppe(host: str, rollen_gruppen=()) -> str:
    """The audience (`aud`) of a token: host, with required roles together with their specification.

    `rollen_gruppen` is the form from `?roles=` or `X-TinySesam-Roles`: a list of groups,
    within a group ONE role suffices, the groups apply together. The representation is
    canonical (sorted, without duplicates) so the same requirement always yields the same string
    — the proxy compares it character by character:

        zielgruppe("app.example.com")                          → "app.example.com"
        zielgruppe("app.example.com", [["redaktion", "admin"]]) → "app.example.com|roles=admin,redaktion"
    """
    h = str(host or "").strip().lower().rstrip(".")
    gruppen = sorted({",".join(sorted({r for r in g if r})) for g in (rollen_gruppen or ()) if any(g)})
    return h + ("|roles=" + ";".join(gruppen) if gruppen else "")


def ausstellen(privat, *, iss: str, aud: str, sub: str, claims: dict, ttl: int, jetzt: int) -> str:
    """A signed token (JWS Compact, `EdDSA`). `claims` are TinySesam's own fields
    without prefix; they end up as `ts_<name>`."""
    kopf = {"alg": "EdDSA", "typ": "JWT", "kid": schluessel_id(oeffentlich_roh(privat))}
    inhalt = {"iss": iss, "aud": aud, "sub": str(sub), "iat": int(jetzt), "nbf": int(jetzt),
              "exp": int(jetzt) + int(ttl), "jti": secrets.token_urlsafe(12)}
    for name, wert in claims.items():
        inhalt[CLAIM_PRAEFIX + name] = wert
    teile = (_b64u(json.dumps(kopf, separators=(",", ":")).encode()) + "."
             + _b64u(json.dumps(inhalt, separators=(",", ":"), ensure_ascii=False).encode("utf-8")))
    return teile + "." + _b64u(privat.sign(teile.encode("ascii")))


def pruefen(oeffentlich: bytes, token: str, *, aud: str, iss: str, jetzt: int) -> Optional[dict]:
    """Check a token the way the proxy does — for tests and diagnostics. None on any error.

    Fail-closed: algorithm fixed to `EdDSA` (the header is not consulted, only compared), signature,
    `iss`, `aud`, `nbf`, `exp`. Without clock tolerance — the proxy gives that, if at all."""
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
    """The value of a `Set-Cookie` header for the gate cookie.

    Always `Secure` and `Path=/`, never `Domain`: the `__Host-` prefix demands exactly that, and the
    browser discards a `__Host-` cookie that lacks one of them. Without `Domain` it applies only to
    the host it was issued for — a token for app-a never even reaches app-b.
    `HttpOnly`: the foreign application's script must not read it."""
    return f"{name}={token}; Path=/; Max-Age={int(ttl)}; Secure; HttpOnly; SameSite=Lax"

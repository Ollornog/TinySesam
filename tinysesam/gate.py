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
* **The key is a key of its own** (T-48, ADR-12): random, never derived from the key that protects the secrets
  at rest. Up to 0.25.x it was derived by HKDF from that base key — whoever read `<db>.key` could mint a token
  for any account. It comes from `TINYSESAM_GATE_KEY`, `gate_key_file` or the database (encrypted with the
  vault), is a keyring with an active and previous keys (`keys.py`), and the proxy learns it from
  `/auth/gate/jwks.json` (`jwk_url`) or as `sign_key` (`tinysesam gate-key`). A derived key of 0.25.x still kept
  as a previous key (note `derived-v1`) is refused at start since the schema baseline (T-111).
* **`typ: tinysesam-gate+jwt`** (RFC 8725 §3.11, T-53): a token says what it is, and `check` refuses any other
  type — no other JWT passes as a gate token. caddy-jwt cannot check `typ` (v1.4.0 has no such option); at the
  proxy the separation rests on the key that signs nothing else, and on `aud`.
* **`aud` carries the host AND the required roles.** A token issued for a check without
  role specification must not be valid on a path that requires `?roles=admin` —
  the proxy sees no roles, only the audience. That is why the role specification is in
  the audience itself (`audience()`), and the proxy names exactly this string there.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Optional

#: The explicit type of a gate token (RFC 8725 §3.11; RFC 7515 §4.1.9 allows leaving out `application/`).
TOKEN_TYPE = "tinysesam-gate+jwt"

#: The limits of the lifetime. Below, the proxy asks almost as often as without a token; above,
#: "revocation takes effect after expiry" becomes a revocation that comes too late (ADR-9, consequences).
TTL_MIN, TTL_MAX = 30, 3600

#: Prefix of the claims TinySesam sets itself — so they collide with no registered claim
#: (RFC 7519) and none of a foreign system.
CLAIM_PREFIX = "ts_"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _read_b64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def public_raw(private) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_b64(private) -> str:
    """The public key the way `caddy-jwt` expects it with `sign_alg EdDSA`:
    the 32 raw bytes, standard Base64."""
    return base64.b64encode(public_raw(private)).decode("ascii")


def key_name_id(public: bytes) -> str:
    """Short identifier of the key (`kid`). The proxy does not need it; when reading
    a token it says which key produced it — the first question after a rotation."""
    return hashlib.sha256(public).hexdigest()[:16]


def audience(host: str, roles_groups=()) -> str:
    """The audience (`aud`) of a token: host, with required roles together with their specification.

    `roles_groups` is the form from `?roles=` or `X-TinySesam-Roles`: a list of groups,
    within a group ONE role suffices, the groups apply together. The representation is
    canonical (sorted, without duplicates) so the same requirement always yields the same string
    — the proxy compares it character by character:

        audience("app.example.com")                            → "app.example.com"
        audience("app.example.com", [["editor", "admin"]])      → "app.example.com|roles=admin,editor"
    """
    h = str(host or "").strip().lower().rstrip(".")
    groups = sorted({",".join(sorted({r for r in g if r})) for g in (roles_groups or ()) if any(g)})
    return h + ("|roles=" + ";".join(groups) if groups else "")


def issue(private, *, iss: str, aud: str, sub: str, claims: dict, ttl: int, now: int) -> str:
    """A signed token (JWS Compact, `EdDSA`). `claims` are TinySesam's own fields
    without prefix; they end up as `ts_<name>`."""
    head = {"alg": "EdDSA", "typ": TOKEN_TYPE, "kid": key_name_id(public_raw(private))}
    content = {"iss": iss, "aud": aud, "sub": str(sub), "iat": int(now), "nbf": int(now),
              "exp": int(now) + int(ttl), "jti": secrets.token_urlsafe(12)}
    for name, value in claims.items():
        content[CLAIM_PREFIX + name] = value
    parts = (_b64u(json.dumps(head, separators=(",", ":")).encode()) + "."
             + _b64u(json.dumps(content, separators=(",", ":"), ensure_ascii=False).encode("utf-8")))
    return parts + "." + _b64u(private.sign(parts.encode("ascii")))


def check(public: bytes, token: str, *, aud: str, iss: str, now: int) -> Optional[dict]:
    """Check a token the way the proxy does — for tests and diagnostics. None on any error.

    Fail-closed: algorithm fixed to `EdDSA` (the header is not consulted, only compared), type `TOKEN_TYPE` (T-53),
    signature, `iss`, `aud`, `nbf`, `exp`. Without clock tolerance — the proxy gives that, if at all."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        k, i, s = str(token or "").split(".")
        head = json.loads(_read_b64u(k))
        if not isinstance(head, dict) or head.get("alg") != "EdDSA" or str(head.get("typ") or "").lower() != TOKEN_TYPE:
            return None
        Ed25519PublicKey.from_public_bytes(public).verify(_read_b64u(s), f"{k}.{i}".encode("ascii"))
        content = json.loads(_read_b64u(i).decode("utf-8"))
    except (ValueError, TypeError, InvalidSignature, UnicodeDecodeError):
        return None
    if not isinstance(content, dict) or content.get("iss") != iss:
        return None
    zg = content.get("aud")
    if not (zg == aud or (isinstance(zg, list) and aud in zg)):
        return None
    try:
        if int(content["nbf"]) > now or int(content["exp"]) <= now:
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return content


def set_cookie(name: str, token: str, ttl: int) -> str:
    """The value of a `Set-Cookie` header for the gate cookie.

    Always `Secure` and `Path=/`, never `Domain`: the `__Host-` prefix demands exactly that, and the
    browser discards a `__Host-` cookie that lacks one of them. Without `Domain` it applies only to
    the host it was issued for — a token for app-a never even reaches app-b.
    `HttpOnly`: the foreign application's script must not read it."""
    return f"{name}={token}; Path=/; Max-Age={int(ttl)}; Secure; HttpOnly; SameSite=Lax"

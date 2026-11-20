"""Paired API keys: HTTP Message Signatures (RFC 9421) with a client-held Ed25519 key (ADR-10, T-32).

The server side of the profile described in ADR-10:

* the signature is selected by `tag="tinysesam"` and must cover `@method` and `@target-uri`, plus the
  RFC 9530 `Content-Digest` whenever the request has a body (checked against the body itself);
* parameters `created` (at most `apikey_signature_max_age` seconds old), `nonce` (single use per key),
  `keyid` (the RFC 7638 JWK thumbprint of the public key), optionally `alg="ed25519"` and `expires`;
* the check runs once per request in a pure-ASGI layer (`SignatureLayer`, installed by
  `TinySesam.install_signatures(app)`) and leaves its outcome in the ASGI scope, where
  `current_user()` picks it up and applies the rules every API key obeys.

The RFC itself is implemented by the optional dependency `http-message-signatures` (extra
`[pairing]`); it is imported lazily so that the core install stays as it is.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import secrets
from typing import Any, Optional

from . import errors

#: The signed application tag that selects TinySesam's signature among others on a request.
TAG = "tinysesam"
#: The only algorithm accepted (RFC 9421 registry name).
ALG = "ed25519"
#: Response header with which the server asks the client to rotate its key (ADR-10).
ROTATE_HEADER = "TinySesam-Key-Rotate"
#: Where the layer leaves its outcome, and its mark "installed", in the ASGI scope.
SCOPE_RESULT = "tinysesam.signature"
SCOPE_INSTALLED = "tinysesam.signatures"
#: Prefix of `api_key.key_hash` for a paired key — never a SHA-256 hex of a bearer string.
HASH_PREFIX = "ed25519:"
#: Purpose of a pairing code in `magic_token`.
PAIRING_PURPOSE = "apikey_pairing"
#: Clock skew tolerated on `created`/`expires` (the library default, stated here for the nonce lifetime).
CLOCK_SKEW = 5
#: Alphabet of the pairing code: no look-alikes (0/O, 1/I), 32 letters → 5 bits per character.
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 16
NONCE_MIN, NONCE_MAX = 8, 128


def _lib():
    """The RFC 9421 library — or `MissingExtra` with the install line."""
    try:
        import http_message_signatures as hms
        from http_message_signatures import algorithms
    except ModuleNotFoundError as e:
        raise errors.MissingExtra(
            "Paired API keys need the extra [pairing] (pip install 'tinysesam[pairing]') — "
            f"missing: {e.name or 'http_message_signatures'}.", extra="pairing") from None
    return hms, algorithms


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    text = str(text or "").strip()
    if not text or len(text) > 128 or any(c not in
                                         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                                         for c in text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def public_key_raw(text: str) -> bytes:
    """The 32 raw bytes of an Ed25519 public key given as base64url — or ValueError."""
    raw = unb64u(text)
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key has 32 bytes")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(raw)      # raises on an invalid point
    return raw


def thumbprint(public_raw: bytes) -> str:
    """RFC 7638 JWK thumbprint of an Ed25519 public key (RFC 8037 `OKP`) — the `keyid` on the wire."""
    jwk = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": b64u(public_raw)}, separators=(",", ":"),
                     sort_keys=True)
    return b64u(hashlib.sha256(jwk.encode("ascii")).digest())


def key_hash(keyid: str) -> str:
    return HASH_PREFIX + keyid


def new_pairing_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    return "-".join(raw[i:i + 4] for i in range(0, CODE_LENGTH, 4))


def normalize_code(code) -> str:
    """Upper case, without separators and blanks — what a person types back is not always what was shown."""
    return "".join(c for c in str(code or "").upper() if c.isalnum())


def code_hash(code) -> str:
    return hashlib.sha256(("pairing:" + normalize_code(code)).encode()).hexdigest()


class _Headers:
    """The header lines of an ASGI scope as the library reads them (`items()` keeps repeated lines)."""

    def __init__(self, raw):
        self._items = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in raw]

    def items(self):
        return list(self._items)

    def __iter__(self):
        return iter(k for k, _ in self._items)

    def __contains__(self, name):
        return any(k.lower() == str(name).lower() for k, _ in self._items)


class _Message:
    def __init__(self, method: str, url: str, raw_headers):
        self.method = method.upper()
        self.url = url
        self.headers = _Headers(raw_headers)


def target_uri(scope, base_url: str = "") -> str:
    """The target URI the client signed: scheme and host from `base_url` when set (the public address,
    also behind a proxy), otherwise from the request; path and query as received."""
    from urllib.parse import quote, urlsplit
    if base_url:
        parts = urlsplit(base_url)
        origin = f"{parts.scheme}://{parts.netloc}"
    else:
        scheme = scope.get("scheme") or "http"
        host = ""
        for k, v in scope.get("headers") or []:
            if k == b"host":
                host = v.decode("latin-1")
                break
        if not host and scope.get("server"):
            h, p = scope["server"][0], scope["server"][1]
            host = h if p in (None, 80 if scheme == "http" else 443) else f"{h}:{p}"
        origin = f"{scheme}://{host}"
    raw = scope.get("raw_path")
    path = raw.decode("latin-1") if raw else quote(scope.get("path") or "/", safe="/%:@!$&'()*+,;=-._~")
    root = scope.get("root_path") or ""
    if root and not path.startswith(root):
        path = root + path
    query = (scope.get("query_string") or b"").decode("latin-1")
    return origin + path + (f"?{query}" if query else "")


class _Resolver:
    def __init__(self, lookup):
        self._lookup = lookup

    def resolve_public_key(self, key_id):
        return self._lookup(key_id)

    def resolve_private_key(self, key_id):   # pragma: no cover - never signs on the server
        raise NotImplementedError


def verify_headers(message: _Message, lookup, max_age: int):
    """Verify TinySesam's signature on the header fields. Returns `(verifier, results, params)`;
    raises `InvalidSignature` (from the library) or `ValueError` with the reason."""
    hms, algorithms = _lib()
    verifier = hms.HTTPMessageVerifier(signature_algorithm=algorithms.ED25519, key_resolver=_Resolver(lookup))
    verifier.max_clock_skew = datetime.timedelta(seconds=CLOCK_SKEW)
    results = verifier.verify(message, max_age=datetime.timedelta(seconds=max_age), expect_tag=TAG,
                              require_components=("@method", "@target-uri"))
    if len(results) != 1:
        raise ValueError("more than one TinySesam signature")
    params = results[0].parameters
    nonce = params.get("nonce")
    if not isinstance(nonce, str) or not NONCE_MIN <= len(nonce) <= NONCE_MAX:
        raise ValueError("nonce missing or of the wrong length")
    if "alg" in params and params["alg"] != ALG:
        raise ValueError("unexpected alg")
    return verifier, results, params


def keyid_of(message: _Message) -> str:
    """The `keyid` of TinySesam's signature in `Signature-Input`, unverified — only to name the key in a refusal."""
    import re
    for name, value in message.headers.items():
        if name.lower() == "signature-input" and f'tag="{TAG}"' in value:
            m = re.search(r'keyid="([A-Za-z0-9_-]{1,128})"', value)
            if m:
                return m.group(1)
    return ""


def ed25519_public(raw: bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    return Ed25519PublicKey.from_public_bytes(raw)


async def read_body(receive) -> tuple:
    """Read the whole request body. Returns `(body, other_messages)` — a disconnect is kept for the app."""
    chunks, other = [], []
    while True:
        message = await receive()
        if message["type"] == "http.request":
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        else:
            other.append(message)
            break
    return b"".join(chunks), other


def replay(body: bytes, other: list, receive):
    """A `receive` that hands the app the body read before, then continues with the original one."""
    pending = [{"type": "http.request", "body": body, "more_body": False}, *other]

    async def _receive():
        if pending:
            return pending.pop(0)
        return await receive()
    return _receive


class SignatureLayer:
    """Pure-ASGI layer for signed requests (ADR-10). Requests without `Signature-Input` pass through untouched.

    It never answers a request itself: it records the outcome in the scope (`SCOPE_RESULT`), and the
    route's guard decides — a public route stays public, a signed request with a bad signature is simply
    not signed in. For a key the owner has asked to rotate it adds `TinySesam-Key-Rotate` to the response."""

    def __init__(self, app, auth):
        self.app = app
        self.auth = auth

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        scope[SCOPE_INSTALLED] = True
        if not self.auth._pairing_active() or not any(k == b"signature-input" for k, _ in scope.get("headers") or []):
            await self.app(scope, receive, send)
            return
        result, receive = await self.auth._signature_check(scope, receive)
        scope[SCOPE_RESULT] = result
        if not result.get("rotate"):
            await self.app(scope, receive, send)
            return
        path = result["rotate_path"]

        async def _send(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.append((ROTATE_HEADER.lower().encode(), path.encode("latin-1")))
                message = {**message, "headers": headers}
            await send(message)
        await self.app(scope, receive, _send)


def result_of(request) -> Optional[dict[str, Any]]:
    """The layer's outcome for this request, or None if it carried no signature (or the layer is missing)."""
    scope = getattr(request, "scope", None) or {}
    return scope.get(SCOPE_RESULT)


def signature_presented(request) -> bool:
    headers = getattr(request, "headers", None)
    return bool(headers is not None and headers.get("signature-input"))


def layer_installed(request) -> bool:
    scope = getattr(request, "scope", None) or {}
    return bool(scope.get(SCOPE_INSTALLED))

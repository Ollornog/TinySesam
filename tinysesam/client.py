"""Reference client for paired API keys (ADR-10, T-32): pairing, signing every request, rotation.

Needs the extra `[pairing]` (`http-message-signatures`); HTTP goes through the standard library, so nothing
else is pulled in. The key pair is generated here and never leaves the machine — the server only learns the
public half.

    from tinysesam.client import PairedClient

    # once: the one-time code from the account page or the admin panel
    client = PairedClient.pair("https://app.example.com", "ABCD-EFGH-JKLM-NPQR", "/etc/myd/tinysesam-key.json")

    # afterwards (the key file holds everything, mode 0600)
    client = PairedClient("/etc/myd/tinysesam-key.json")
    r = client.request("POST", "/api/things", json={"name": "x"})
    r.status, r.json()

Every request carries an RFC 9421 signature over method, target URI and (with a body) `Content-Digest`, with a
fresh nonce and `created`. When a response says `TinySesam-Key-Rotate`, the client generates a new key pair,
stores it as *pending* first, registers it (signed with the current key) and only then switches — so a crash in
between never loses the working key. Requests already in flight keep working (the server's overlap window).

Command line: `python -m tinysesam.client pair <base_url> <code> <key_file>` and
`python -m tinysesam.client request <key_file> <METHOD> <path> [--json '{"…": …}']`.
"""
from __future__ import annotations

import datetime
import json as _json
import logging
import os
import secrets
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ._signatures import ROTATE_HEADER, TAG, _lib, b64u, thumbprint, unb64u

log = logging.getLogger("tinysesam.client")

#: Default paths of the TinySesam routes, relative to the base URL.
PAIR_PATH = "/auth/apikeys/pair"
ROTATE_PATH = "/auth/apikeys/rotate"


class PairingError(RuntimeError):
    """The server refused the pairing (unknown/used/expired code, signature, key already registered)."""

    def __init__(self, status: int, detail: str):
        super().__init__(f"pairing refused ({status}): {detail}")
        self.status = status
        self.detail = detail


@dataclass
class Response:
    status: int
    headers: dict = field(default_factory=dict)      # lower-case names
    body: bytes = b""

    def json(self) -> Any:
        return _json.loads(self.body or b"null")


#: `transport(method, url, headers, body) -> Response` — replaceable (tests, a proxy, another HTTP stack).
Transport = Callable[[str, str, dict, bytes], Response]


def urllib_transport(method: str, url: str, headers: dict, body: bytes, timeout: float = 30) -> Response:
    req = urllib.request.Request(url, data=body if body else None, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:      # noqa: S310 - the caller's own server
            return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read())
    except urllib.error.HTTPError as e:
        return Response(e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read() or b"")


def _new_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.generate()


def _seed(key) -> str:
    from cryptography.hazmat.primitives import serialization
    return b64u(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption()))


def _public(key) -> str:
    from cryptography.hazmat.primitives import serialization
    return b64u(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def _load(seed: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(unb64u(seed))


class _Message:
    def __init__(self, method: str, url: str, headers: dict):
        from http_message_signatures.structures import CaseInsensitiveDict
        self.method = method.upper()
        self.url = url
        self.headers = CaseInsensitiveDict(headers)


def sign(method: str, url: str, headers: dict, body: bytes, key) -> dict:
    """Headers with an RFC 9421 signature in TinySesam's profile (tag, nonce, created, `Content-Digest`)."""
    hms, algorithms = _lib()

    class _Keys:
        def resolve_private_key(self, key_id):
            return key

        def resolve_public_key(self, key_id):        # pragma: no cover - never verifies here
            return key.public_key()

    message = _Message(method, url, headers)
    signer = hms.HTTPMessageSigner(signature_algorithm=algorithms.ED25519, key_resolver=_Keys())
    signer.sign(message, key_id=thumbprint(unb64u(_public(key))), tag=TAG, nonce=secrets.token_urlsafe(18),
                created=datetime.datetime.now(datetime.timezone.utc),
                covered_component_ids=("@method", "@target-uri"), body=body if body else None)
    return dict(message.headers.items())


def _write_private(path: str, state: dict) -> None:
    """Write the key file atomically with mode 0600 — it holds the private key."""
    directory = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(directory, f".{os.path.basename(path)}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            _json.dump(state, fh)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


class PairedClient:
    """A client holding a paired key. Thread-safe; one instance per key file."""

    def __init__(self, key_file: str, transport: Optional[Transport] = None):
        self.key_file = key_file
        self.transport: Transport = transport or urllib_transport
        self._lock = threading.Lock()
        with open(key_file, encoding="utf-8") as fh:
            self._state = _json.load(fh)

    # ---------- pairing ----------
    @classmethod
    def pair(cls, base_url: str, code: str, key_file: str, *, pair_path: str = PAIR_PATH,
             transport: Optional[Transport] = None) -> "PairedClient":
        """Generate a key pair, redeem the one-time `code` with its public half (the request is signed with the
        new key — proof of possession) and store the key file. Raises `PairingError` on refusal."""
        transport = transport or urllib_transport
        key = _new_key()
        base_url = base_url.rstrip("/")
        body = _json.dumps({"code": code, "public_key": _public(key)}).encode()
        url = base_url + pair_path
        headers = sign("POST", url, {"Content-Type": "application/json"}, body, key)
        r = transport("POST", url, headers, body)
        if r.status != 200:
            try:
                detail = str(r.json().get("detail"))
            except Exception:
                detail = r.body[:200].decode("utf-8", "replace")
            raise PairingError(r.status, detail)
        answer = r.json()
        _write_private(key_file, {"base_url": base_url, "keyid": answer["keyid"], "private_key": _seed(key),
                                  "pending": None, "rotate_path": answer.get("rotate_path") or ROTATE_PATH,
                                  "key_id": answer.get("id")})
        return cls(key_file, transport)

    # ---------- requests ----------
    @property
    def keyid(self) -> str:
        return self._state["keyid"]

    def request(self, method: str, path: str, *, json: Any = None, data: bytes = b"",
                headers: Optional[dict] = None) -> Response:
        """Send a signed request to `base_url + path`. Completes a pending rotation first and starts one when the
        server asks for it (after the response, which is returned unchanged)."""
        if self._state.get("pending"):
            try:
                self._complete_rotation()
            except Exception as e:          # the current key still works; try again next time
                log.warning("pending key rotation not completed, will retry on the next request: %s", e)
        r = self._send(method, path, json=json, data=data, headers=headers)
        if r.headers.get(ROTATE_HEADER.lower()):
            try:
                self._rotate(r.headers[ROTATE_HEADER.lower()])
            except Exception as e:          # the answer the caller asked for is already there
                log.warning("key rotation failed, will retry on the next request: %s", e)
        return r

    def _send(self, method: str, path: str, *, json: Any = None, data: bytes = b"",
              headers: Optional[dict] = None, key=None) -> Response:
        hdrs = dict(headers or {})
        body = data or b""
        if json is not None:
            body = _json.dumps(json).encode()
            hdrs.setdefault("Content-Type", "application/json")
        with self._lock:
            key = key or _load(self._state["private_key"])
            url = self._state["base_url"] + path
        return self.transport(method.upper(), url, sign(method, url, hdrs, body, key), body)

    # ---------- rotation ----------
    def _rotate(self, path: str) -> None:
        with self._lock:
            if not self._state.get("pending"):
                self._state["pending"] = _seed(_new_key())
                self._state["rotate_path"] = path or self._state.get("rotate_path") or ROTATE_PATH
                _write_private(self.key_file, self._state)       # pending is on disk BEFORE the server knows it
        self._complete_rotation()

    def _complete_rotation(self) -> None:
        with self._lock:
            pending = self._state.get("pending")
            path = self._state.get("rotate_path") or ROTATE_PATH
        if not pending:
            return
        new = _load(pending)
        r = self._send("POST", path, json={"public_key": _public(new)})
        if r.status != 200:
            raise RuntimeError(f"rotation refused ({r.status}): {r.body[:200]!r}")
        with self._lock:
            self._state.update(private_key=pending, pending=None, keyid=r.json().get("keyid") or
                               thumbprint(unb64u(_public(new))))
            _write_private(self.key_file, self._state)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m tinysesam.client",
                                 description="Reference client for TinySesam paired API keys (ADR-10)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pair", help="redeem a one-time pairing code and store the key file (mode 0600)")
    p.add_argument("base_url")
    p.add_argument("code")
    p.add_argument("key_file")
    q = sub.add_parser("request", help="send one signed request and print the answer")
    q.add_argument("key_file")
    q.add_argument("method")
    q.add_argument("path")
    q.add_argument("--json", dest="json_body", default=None, help="JSON body")
    a = ap.parse_args(argv)
    if a.cmd == "pair":
        try:
            client = PairedClient.pair(a.base_url, a.code, a.key_file)
        except PairingError as e:
            print(e)
            return 1
        print(f"paired, key file {client.key_file} (mode 0600)")
        return 0
    client = PairedClient(a.key_file)
    r = client.request(a.method, a.path, json=_json.loads(a.json_body) if a.json_body else None)
    print(r.status)
    print(r.body.decode("utf-8", "replace"))
    return 0 if r.status < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())

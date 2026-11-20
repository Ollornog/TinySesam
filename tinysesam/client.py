"""Reference client for services (T-60, ADR-13): pairing, tokens, key rotation — so nobody builds it themselves.

A service (a daemon, a backup job, a script on a server) reaches an application behind TinySesam with a short-lived
access token. It gets the token with `client_credentials` and authenticates with `private_key_jwt` (RFC 7523): a
small JWT signed with its own key. The key pair is created HERE and never leaves the machine — TinySesam only learns
the public half, once, when the service is paired with a one-time code from the account page or the admin panel.

Needs the extra `[services]` (joserfc, which builds on `cryptography`); HTTP goes through the standard library.

Command line (`tinysesam-client`, or `python -m tinysesam.client`)::

    tinysesam-client pair https://auth.example.com ABCD-EFGH-JKMN-PQRS      # once; writes the key file (0600)
    tinysesam-client token                                                 # prints a valid access token
    tinysesam-client request GET https://app.example.com/api/things        # one call with the token
    tinysesam-client rotate                                                # new key now (otherwise automatic)
    tinysesam-client info                                                  # client ID, key ID, expiry — no secret

The key file is `--key-file`, else `$TINYSESAM_CLIENT_KEY_FILE`, else `$XDG_CONFIG_HOME/tinysesam/client.json`.

In Python::

    from tinysesam.client import ServiceClient
    sc = ServiceClient("/etc/myservice/tinysesam.json")
    httpx.get("https://app.example.com/api/things", auth=sc.httpx_auth())
    requests.get("https://app.example.com/api/things", auth=sc.requests_auth())

Tokens are cached per resource and fetched again shortly before they expire; a 401 from the application drops the
cached token and tries once more. When the key is older than half its lifetime, the next token request rotates it
first: the new key is written to the file as *pending* BEFORE TinySesam learns it, so a crash in between never loses
the working key. Several processes may share one key file — each re-reads it when it changed.
"""
from __future__ import annotations

import base64
import hashlib
import json as _json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

log = logging.getLogger("tinysesam.client")

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ASSERTION_TYP = "client-authentication+jwt"
PAIRING_TYP = "tinysesam-pairing+jwt"
KEY_TYP = "tinysesam-key+jwt"
#: Lifetime of the assertions this client signs (the server allows up to 300 s).
ASSERTION_SEC = 60
#: A cached token is fetched again this many seconds before it expires.
MARGIN_SEC = 60
ALGORITHMS = ("Ed25519", "ES256")
FILE_VERSION = 1


class ServiceError(RuntimeError):
    """TinySesam refused (pairing, token, rotation): HTTP status, OAuth `error` and description."""

    def __init__(self, status: int, error: str, description: str = ""):
        super().__init__(f"{error} ({status}){': ' + description if description else ''}")
        self.status = status
        self.error = error
        self.description = description


@dataclass
class Response:
    status: int
    headers: dict = field(default_factory=dict)     # lower-case names
    body: bytes = b""

    def json(self) -> Any:
        return _json.loads(self.body or b"null")


#: `transport(method, url, headers, body) -> Response` — replaceable (tests, a proxy, another HTTP stack).
Transport = Callable[[str, str, dict, bytes], Response]


def urllib_transport(method: str, url: str, headers: dict, body: bytes, timeout: float = 30) -> Response:
    if urllib.parse.urlsplit(url).scheme not in ("https", "http"):
        raise ValueError(f"not an http(s) URL: {url!r}")
    req = urllib.request.Request(url, data=body or None, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:      # noqa: S310 - scheme checked above
            return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read())
    except urllib.error.HTTPError as e:
        return Response(e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read() or b"")


def default_key_file() -> str:
    env = os.environ.get("TINYSESAM_CLIENT_KEY_FILE", "").strip()
    if env:
        return env
    base = os.environ.get("XDG_CONFIG_HOME", "").strip() or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "tinysesam", "client.json")


# ---------- keys and JWTs (joserfc) ----------

def _lib():
    try:
        from joserfc import jws
        from joserfc.jwk import ECKey, OKPKey
    except ImportError as e:
        raise RuntimeError("tinysesam.client needs the extra [services]: pip install 'tinysesam[services]'") from e
    return jws, OKPKey, ECKey


def new_key(alg: str = "Ed25519") -> dict:
    """A new key pair as a private JWK (dict) with `kid` (RFC 7638 thumbprint) and `alg`."""
    if alg not in ALGORITHMS:
        raise ValueError(f"alg must be one of {ALGORITHMS}")
    _, OKPKey, ECKey = _lib()
    key = OKPKey.generate_key("Ed25519") if alg == "Ed25519" else ECKey.generate_key("P-256")
    return {"kid": key.thumbprint(), "alg": alg, "jwk": key.as_dict(private=True)}


def public_jwk(key: dict) -> dict:
    return {k: v for k, v in key["jwk"].items() if k in ("kty", "crv", "x", "y")}


def sign(key: dict, typ: str, claims: dict) -> str:
    """A compact JWS of `claims`, signed with `key`, header `alg`, `typ` and `kid`."""
    jws, OKPKey, ECKey = _lib()
    k = (OKPKey if key["jwk"]["kty"] == "OKP" else ECKey).import_key(key["jwk"])
    header = {"alg": key["alg"], "typ": typ, "kid": key["kid"]}
    return jws.serialize_compact(header, _json.dumps(claims, separators=(",", ":")).encode(), k,
                                 algorithms=[key["alg"]])


def _claims(issuer: str, now: int, **extra) -> dict:
    d = {"aud": issuer, "iat": now, "exp": now + ASSERTION_SEC, "jti": secrets.token_urlsafe(24)}
    d.update(extra)
    return d


def _write_private(path: str, state: dict) -> None:
    """Write the key file atomically with mode 0600 — it holds the private key. The directory is created 0700."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    tmp = os.path.join(directory, f".{os.path.basename(path)}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            _json.dump(state, fh, indent=1)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _refused(r: Response) -> ServiceError:
    try:
        j = r.json()
        return ServiceError(r.status, str(j.get("error") or "error"), str(j.get("error_description") or ""))
    except Exception:
        return ServiceError(r.status, "error", r.body[:200].decode("utf-8", "replace"))


class ServiceClient:
    """A paired service. Thread-safe; one instance per key file and process."""

    def __init__(self, key_file: Optional[str] = None, *, transport: Optional[Transport] = None,
                 margin: int = MARGIN_SEC, auto_rotate: bool = True):
        self.key_file = key_file or default_key_file()
        self.transport: Transport = transport or urllib_transport
        self.margin = int(margin)
        self.auto_rotate = auto_rotate
        self._lock = threading.RLock()
        self._tokens: dict = {}
        self._mtime: Optional[tuple] = None
        self._state: dict = {}
        self._reload()

    # ---------- pairing ----------
    @classmethod
    def pair(cls, base_url: str, code: str, key_file: Optional[str] = None, *, alg: str = "Ed25519",
             transport: Optional[Transport] = None, **kwargs) -> "ServiceClient":
        """Create a key pair, redeem the one-time `code` with its public half and a proof of possession, store the
        key file (mode 0600). Raises `ServiceError` on a refusal; an existing key file is never overwritten."""
        transport = transport or urllib_transport
        key_file = key_file or default_key_file()
        if os.path.exists(key_file):
            raise FileExistsError(f"{key_file} exists — a second service needs its own key file")
        issuer = base_url.rstrip("/")
        meta = transport("GET", issuer + "/.well-known/oauth-authorization-server", {"Accept": "application/json"},
                         b"")
        if meta.status != 200:
            raise _refused(meta)
        m = meta.json()
        # RFC 8414 §3.3: the issuer in the document must be the one we asked — otherwise a mix-up.
        if m.get("issuer") != issuer:
            raise ServiceError(meta.status, "invalid_issuer", f"the server says its issuer is {m.get('issuer')!r}")
        if "client_credentials" not in (m.get("grant_types_supported") or []):
            raise ServiceError(meta.status, "unsupported", "this TinySesam does not accept services "
                                                           "(oauth_service_clients is off)")
        key = new_key(alg)
        normal = "".join(z for z in code.upper() if z not in "- \t")
        nonce = base64.urlsafe_b64encode(hashlib.sha256(normal.encode("ascii")).digest()).decode().rstrip("=")
        proof = sign(key, PAIRING_TYP, _claims(issuer, int(time.time()), nonce=nonce))
        body = _json.dumps({"code": code, "jwk": public_jwk(key), "proof": proof}).encode()
        r = transport("POST", issuer + "/auth/oauth/pair", {"Content-Type": "application/json"}, body)
        if r.status != 201:
            raise _refused(r)
        a = r.json()
        key["expires_at"] = a.get("key_expires_at")
        key["created_at"] = int(time.time())
        _write_private(key_file, {"version": FILE_VERSION, "issuer": a["issuer"], "client_id": a["client_id"],
                                  "token_endpoint": a["token_endpoint"], "key_endpoint": a["key_endpoint"],
                                  "resources": a.get("resources") or [], "key": key, "pending": None})
        return cls(key_file, transport=transport, **kwargs)

    # ---------- state ----------
    def _reload(self) -> None:
        """Read the key file if it changed (another process rotated the key)."""
        st = os.stat(self.key_file)
        if self._mtime == (st.st_mtime_ns, st.st_size):
            return
        if st.st_mode & 0o077:
            log.warning("%s is readable by others (mode %o) — it holds a private key: chmod 600", self.key_file,
                        st.st_mode & 0o777)
        with open(self.key_file, encoding="utf-8") as fh:
            state = _json.load(fh)
        if state.get("version") != FILE_VERSION or not state.get("client_id"):
            raise ValueError(f"{self.key_file} is no tinysesam-client key file")
        self._state, self._mtime = state, (st.st_mtime_ns, st.st_size)

    def _save(self) -> None:
        _write_private(self.key_file, self._state)
        st = os.stat(self.key_file)
        self._mtime = (st.st_mtime_ns, st.st_size)

    @property
    def client_id(self) -> str:
        return self._state["client_id"]

    @property
    def kid(self) -> str:
        return self._state["key"]["kid"]

    @property
    def resources(self) -> list:
        return list(self._state.get("resources") or [])

    def info(self) -> dict:
        """What can be shown: no private key, no token."""
        k = self._state["key"]
        return {"issuer": self._state["issuer"], "client_id": self.client_id, "resources": self.resources,
                "kid": k["kid"], "alg": k["alg"], "key_created_at": k.get("created_at"),
                "key_expires_at": k.get("expires_at"), "pending_rotation": bool(self._state.get("pending"))}

    def _assertion(self, key: dict) -> str:
        return sign(key, ASSERTION_TYP, _claims(self._state["issuer"], int(time.time()), iss=self.client_id,
                                                sub=self.client_id))

    def _post_form(self, url: str, form: dict) -> Response:
        return self.transport("POST", url, {"Content-Type": "application/x-www-form-urlencoded",
                                            "Accept": "application/json"}, urllib.parse.urlencode(form).encode())

    # ---------- tokens ----------
    def token(self, resource: Optional[str] = None) -> str:
        """A valid access token for `resource` (may be left out when the service has exactly one)."""
        with self._lock:
            self._reload()
            if self._state.get("pending") or (self.auto_rotate and self._rotation_due()):
                try:
                    self.rotate_key()
                except Exception as e:      # the current key still works — try again with the next token
                    log.warning("key rotation failed, the current key stays in use: %s", e)
            now = time.time()
            cached = self._tokens.get(resource or "")
            if cached and cached[1] - self.margin > now:
                return cached[0]
            form = {"grant_type": "client_credentials", "client_id": self.client_id,
                    "client_assertion_type": ASSERTION_TYPE, "client_assertion": self._assertion(self._state["key"])}
            if resource:
                form["resource"] = resource
            r = self._post_form(self._state["token_endpoint"], form)
            if r.status != 200:
                raise _refused(r)
            a = r.json()
            self._tokens[resource or ""] = (a["access_token"], now + int(a.get("expires_in") or 0))
            return a["access_token"]

    def invalidate(self, resource: Optional[str] = None) -> None:
        """Forget the cached token (after a 401 from the application)."""
        with self._lock:
            self._tokens.pop(resource or "", None)

    # ---------- key rotation ----------
    def _rotation_due(self) -> bool:
        k = self._state["key"]
        created, expires = k.get("created_at"), k.get("expires_at")
        return bool(created and expires and time.time() >= created + (expires - created) / 2)

    def rotate_key(self) -> str:
        """Replace the key now: the new one is on disk as *pending* before TinySesam learns it. Returns its `kid`."""
        with self._lock:
            self._reload()
            if not self._state.get("pending"):
                self._state["pending"] = new_key(self._state["key"]["alg"])
                self._save()
            return self._complete_rotation()

    def _complete_rotation(self) -> str:
        pending = self._state["pending"]
        now = int(time.time())
        form = {"client_id": self.client_id, "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": self._assertion(self._state["key"]),
                "jwk": _json.dumps(public_jwk(pending)),
                "proof": sign(pending, KEY_TYP, _claims(self._state["issuer"], now, sub=self.client_id))}
        r = self._post_form(self._state["key_endpoint"], form)
        if r.status != 200:
            raise _refused(r)
        a = r.json()
        pending["created_at"] = now
        pending["expires_at"] = a.get("key_expires_at")
        self._state["key"], self._state["pending"] = pending, None
        self._save()
        self._tokens.clear()
        log.info("key rotated: %s (the previous one stays valid until %s)", pending["kid"], a.get("previous_valid_until"))
        return pending["kid"]

    # ---------- HTTP libraries ----------
    def httpx_auth(self, resource: Optional[str] = None):
        """An `httpx.Auth`: sets the bearer token, and after a 401 fetches a new one and tries once more. With an
        `AsyncClient` the token request itself is synchronous (short, cached for minutes)."""
        import httpx
        client = self

        class TinySesamAuth(httpx.Auth):
            def auth_flow(self, request):
                request.headers["Authorization"] = "Bearer " + client.token(resource)
                response = yield request
                if response.status_code == 401:
                    client.invalidate(resource)
                    request.headers["Authorization"] = "Bearer " + client.token(resource)
                    yield request

        return TinySesamAuth()

    def requests_auth(self, resource: Optional[str] = None):
        """A `requests` auth object: sets the bearer token, and after a 401 fetches a new one and tries once more."""
        import requests
        client = self

        class TinySesamAuth(requests.auth.AuthBase):
            def __call__(self, r):
                r.headers["Authorization"] = "Bearer " + client.token(resource)
                r.register_hook("response", self._again)
                return r

            def _again(self, response, **kwargs):
                if response.status_code != 401 or getattr(response.request, "_tinysesam_again", False):
                    return response
                client.invalidate(resource)
                _ = response.content
                response.close()
                again = response.request.copy()
                again._tinysesam_again = True
                again.headers["Authorization"] = "Bearer " + client.token(resource)
                new = response.connection.send(again, **kwargs)
                new.history.append(response)
                new.request = again
                return new

        return TinySesamAuth()

    def request(self, method: str, url: str, *, resource: Optional[str] = None, data: bytes = b"",
                headers: Optional[dict] = None) -> Response:
        """One request with the bearer token through the transport (standard library) — 401 → new token, once."""
        for attempt in (0, 1):
            h = dict(headers or {})
            h["Authorization"] = "Bearer " + self.token(resource)
            r = self.transport(method.upper(), url, h, data)
            if r.status != 401 or attempt:
                return r
            self.invalidate(resource)
        return r  # pragma: no cover


def main(argv=None) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(prog="tinysesam-client",
                                 description="Reference client for TinySesam services: client_credentials with "
                                             "private_key_jwt (ADR-13). The private key never leaves this machine.")
    ap.add_argument("--key-file", default=None, help=f"key file (default: {default_key_file()})")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pair", help="redeem a one-time pairing code and write the key file (mode 0600)")
    p.add_argument("base_url", help="TinySesam's address (the issuer), e.g. https://auth.example.com")
    p.add_argument("code", help="the pairing code from the account page or the admin panel")
    p.add_argument("--alg", choices=ALGORITHMS, default="Ed25519")
    t = sub.add_parser("token", help="print a valid access token (for curl and scripts)")
    t.add_argument("--resource", default=None)
    q = sub.add_parser("request", help="send one request with the token and print status and body")
    q.add_argument("method")
    q.add_argument("url")
    q.add_argument("--resource", default=None)
    q.add_argument("--data", default=None, help="request body (sent as is)")
    sub.add_parser("rotate", help="replace the key now (it also rotates by itself at half its lifetime)")
    sub.add_parser("info", help="client ID, key ID and expiry — no secret")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "pair":
            c = ServiceClient.pair(a.base_url, a.code, a.key_file, alg=a.alg)
            print(f"paired: client {c.client_id}, key file {c.key_file} (mode 0600)")
            return 0
        c = ServiceClient(a.key_file)
        if a.cmd == "token":
            print(c.token(a.resource))
        elif a.cmd == "request":
            r = c.request(a.method, a.url, resource=a.resource, data=(a.data or "").encode())
            print(r.status)
            sys.stdout.write(r.body.decode("utf-8", "replace") + "\n")
            return 0 if r.status < 400 else 1
        elif a.cmd == "rotate":
            print(f"new key {c.rotate_key()}")
        else:
            print(_json.dumps(c.info(), indent=1))
    except (ServiceError, OSError, ValueError, RuntimeError) as e:
        print(f"tinysesam-client: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

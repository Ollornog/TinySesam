"""A real OpenID provider for the browser suites (T-107): authorization code flow with PKCE over HTTP, on a loopback
port, so that a provider's account signs in the way a person does — the browser leaves TinySesam's sign-in page for
the provider, picks the account on the provider's page and comes back through `/auth/oidc/callback`; TinySesam fetches
discovery, the token and the key set itself and checks the ID token (RS256) as it checks any provider's.

  idp = TestIdP({"kim": {"email": "kim@example.test", "groups": ["team-docs"]}})
  config: oidc_issuer = idp.issuer, oidc_client_id = idp.client_id, oidc_client_secret = idp.client_secret
  browser: … on the provider's page click `#idp-kim` (`TestIdP.PICK`)

What it checks of the client: the client id, the one redirect URI it learnt from the first request, the client secret
(form post), the PKCE verifier (S256), a code used once. It issues no refresh token and never asks for consent. Test
material only — the key is made per instance and thrown away with it.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import secrets
import time
import tomllib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from _browser_stack import serve


#: T-162: a line of the optional provider block of a deployment file (deploy/ex1, deploy/ex4): commented out as
#: `#oidc_<field> = <value>`, the operator switches the block on by removing the `#` (the deployment's README).
_PROVIDER_LINE = re.compile(r"^#(oidc_[a-z_]+ = .+)$", re.M)
#: What the block must say: switched on, the provider, the client, its secret through the environment, the `groups`
#: scope and the group that becomes the example's role.
PROVIDER_KEYS = ("oidc_enabled", "oidc_issuer", "oidc_client_id", "oidc_client_secret", "oidc_scopes",
                 "oidc_group_role_map")


def deploy_provider(toml: str, where: str) -> tuple[str, dict]:
    """The deployment file `where` with its optional provider block switched on — every `#oidc_… = …` line without its
    `#`, as the README tells the operator — and the block's values. The suites build the example from exactly this, so
    a block that is missing, incomplete or maps the group to another role turns its cell red."""
    assert not re.search(r"^oidc_", toml, re.M), f"{where}: the provider block is optional — its lines start with #"
    values = tomllib.loads("\n".join(_PROVIDER_LINE.findall(toml)))
    missing = [k for k in PROVIDER_KEYS if k not in values]
    assert not missing and values["oidc_enabled"] is True, \
        f"{where}: the provider block lacks {missing or 'oidc_enabled = true'}"
    assert values["oidc_client_secret"].startswith("env:"), f"{where}: the client secret only as env:NAME"
    assert "groups" in values["oidc_scopes"].split(), f"{where}: oidc_scopes must ask for groups"
    return _PROVIDER_LINE.sub(r"\1", toml), values


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _int_b64u(n: int) -> str:
    return _b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))


class TestIdP:
    """The provider; `users` maps a sign-in name to its extra claims (`email`, `groups`, `name`, …). `sub` is
    `<name>-sub` unless the claims name one."""

    #: The button on the provider's page that signs in as `name`.
    PICK = "#idp-{name}"

    def __init__(self, users: dict[str, dict], *, client_id: str = "ts-matrix",
                 client_secret: str = "matrix-secret"):
        self.users = {name: {"sub": f"{name}-sub", "preferred_username": name, **claims}
                      for name, claims in users.items()}
        self.client_id, self.client_secret = client_id, client_secret
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = _b64u(secrets.token_bytes(8))
        self.redirect_uri = ""
        self._requests: dict[str, dict] = {}
        self._codes: dict[str, dict] = {}
        self._tokens: dict[str, str] = {}
        #: Every sign-in the provider granted, by name — the suites read whose round went through the provider.
        self.signed_in: list[str] = []
        self.port, self.server = serve(self._app())
        self.issuer = f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.server.should_exit = True

    def _id_token(self, claims: dict) -> str:
        head = _b64u(json.dumps({"alg": "RS256", "typ": "JWT", "kid": self.kid}).encode())
        body = _b64u(json.dumps(claims).encode())
        signature = self.key.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return f"{head}.{body}.{_b64u(signature)}"

    def _app(self) -> FastAPI:
        app = FastAPI()

        @app.get("/.well-known/openid-configuration")
        def discovery():
            return {"issuer": self.issuer, "authorization_endpoint": f"{self.issuer}/authorize",
                    "token_endpoint": f"{self.issuer}/token", "userinfo_endpoint": f"{self.issuer}/userinfo",
                    "jwks_uri": f"{self.issuer}/jwks", "response_types_supported": ["code"],
                    "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_post"]}

        @app.get("/jwks")
        def jwks():
            numbers = self.key.public_key().public_numbers()
            return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                              "n": _int_b64u(numbers.n), "e": _int_b64u(numbers.e)}]}

        @app.get("/authorize")
        def authorize(request: Request):
            q = request.query_params
            if (q.get("client_id") != self.client_id or q.get("response_type") != "code" or not q.get("state")
                    or q.get("code_challenge_method") != "S256" or not q.get("code_challenge")):
                return HTMLResponse("<p id=idp-error>invalid request</p>", status_code=400)
            self.redirect_uri = self.redirect_uri or q.get("redirect_uri", "")
            if q.get("redirect_uri") != self.redirect_uri:
                return HTMLResponse("<p id=idp-error>unknown redirect_uri</p>", status_code=400)
            tx = secrets.token_urlsafe(16)
            self._requests[tx] = dict(q)
            buttons = "".join(f"<button name=user value='{html.escape(n)}' id='idp-{html.escape(n)}'>"
                              f"Sign in as {html.escape(n)}</button>" for n in self.users)
            return HTMLResponse(f"<!doctype html><title>Test provider</title><link rel=icon href=\"data:,\">"
                                f"<h1>Test provider</h1>"
                                f"<form method=post action=/authorize><input type=hidden name=tx value='{tx}'>"
                                f"{buttons}</form>")

        @app.post("/authorize")
        def pick(tx: str = Form(...), user: str = Form(...)):
            req = self._requests.pop(tx, None)
            if req is None or user not in self.users:
                return HTMLResponse("<p id=idp-error>expired</p>", status_code=400)
            code = secrets.token_urlsafe(24)
            self._codes[code] = {"user": user, **req, "at": int(time.time())}
            self.signed_in.append(user)
            sep = "&" if "?" in req["redirect_uri"] else "?"
            from urllib.parse import urlencode
            return RedirectResponse(f"{req['redirect_uri']}{sep}{urlencode({'code': code, 'state': req['state']})}",
                                    status_code=303)

        @app.post("/token")
        def token(grant_type: str = Form(""), code: str = Form(""), redirect_uri: str = Form(""),
                  client_id: str = Form(""), client_secret: str = Form(""), code_verifier: str = Form("")):
            grant = self._codes.pop(code, None)
            challenge = _b64u(hashlib.sha256(code_verifier.encode("ascii")).digest())
            if (grant_type != "authorization_code" or grant is None or client_id != self.client_id
                    or not secrets.compare_digest(client_secret, self.client_secret)
                    or redirect_uri != grant["redirect_uri"] or challenge != grant["code_challenge"]):
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            now = int(time.time())
            claims = {**self.users[grant["user"]], "iss": self.issuer, "aud": self.client_id, "iat": now,
                      "exp": now + 300, "auth_time": grant["at"], "nonce": grant.get("nonce", "")}
            access = secrets.token_urlsafe(24)
            self._tokens[access] = grant["user"]
            return {"access_token": access, "token_type": "Bearer", "expires_in": 300,
                    "id_token": self._id_token(claims)}

        @app.get("/userinfo")
        def userinfo(request: Request):
            access = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
            user = self._tokens.get(access)
            if user is None:
                return JSONResponse({"error": "invalid_token"}, status_code=401)
            return self.users[user]

        return app

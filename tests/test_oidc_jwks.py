"""OIDC: the JWKS must survive a key rotation at the provider.

Up to 0.18.0 the key set was fetched **once** and kept for the lifetime of the process.
Providers rotate their signing keys regularly, though (Keycloak, Entra, Auth0).
After a rotation every fresh ID token names a `kid` that the cached set does not know —
and thus EVERY login failed at the signature until someone restarted the service. An
outage that nobody could recognize as a configuration error.

This suite runs without a network: discovery, token endpoint and JWKS are stand-ins.
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

r = Report("OIDC — JWKS and key rotation")

META = {"issuer": "https://id.example.com", "jwks_uri": "https://id.example.com/jwks",
        "token_endpoint": "https://id.example.com/token",
        "authorization_endpoint": "https://id.example.com/auth"}


def fresh_client():
    c = OIDCClient("https://id.example.com", "cid", "geheim", "openid")
    c._meta, c._meta_when = dict(META), time.time()
    return c


# ---------- 1) The set is cached, but ages ----------
fetches = []


def counting_fetching(c):
    """Put a counter under `_jwkset`, without rebuilding the cache logic."""
    module = sys.modules["tinysesam.oidc"]

    class FakeJWK:
        @staticmethod
        def import_key_set(data):
            return f"set-{data['nr']}"

    class FakeResponse:
        def __init__(self, nr):
            self._nr = nr

        def json(self):
            return {"nr": self._nr}

    def fake_get(url, **kw):
        fetches.append(url)
        return FakeResponse(len(fetches))

    fake_httpx = types.SimpleNamespace(get=fake_get)
    fake_jose = types.SimpleNamespace(JsonWebKey=FakeJWK)
    sys.modules["httpx"] = fake_httpx
    sys.modules["authlib.jose"] = fake_jose
    return module


c = fresh_client()
real_httpx = sys.modules.get("httpx")
real_jose = sys.modules.get("authlib.jose")
counting_fetching(c)
try:
    first = c._jwkset()
    second = c._jwkset()
    r.check("the set is cached (one fetch for two calls)",
            first == second and len(fetches) == 1, f"{len(fetches)} fetches")

    third = c._jwkset(enforce=True)
    r.check("a forced fetch fetches anew", third != first and len(fetches) == 2,
            f"{len(fetches)} fetches, result {third!r}")

    c._jwks_when -= c.JWKS_TTL + 1
    fourth = c._jwkset()
    r.check("after the lifetime has expired it is fetched anew on its own",
            fourth != third and len(fetches) == 3, f"{len(fetches)} fetches")
finally:
    if real_httpx is not None:
        sys.modules["httpx"] = real_httpx
    if real_jose is not None:
        sys.modules["authlib.jose"] = real_jose
    else:
        sys.modules.pop("authlib.jose", None)

# ---------- 2) The throttle against foreign load ----------
c2 = fresh_client()
c2._jwks, c2._jwks_when = "irgendwas", time.time()
r.check("directly after a fetch the refresh is blocked", not c2._jwks_refreshable(),
        "every broken id_token could trigger a fetch at the provider")
c2._jwks_when -= c2.JWKS_MIN_GAP + 1
r.check("after the minimum interval it is allowed again", c2._jwks_refreshable(),
        "the throttle never opens — then it does not help with a rotation either")


# ---------- 3) The actual case: rotation in the middle of operation ----------
# `exchange()` fetches a token, verifies it against the set, and is to
# fetch anew ONCE on a signature error and try again.
class FakeClaims(dict):
    def validate(self, *a, **k):
        pass


def make_exchange_environment(c, attempts):
    """httpx.post returns an id_token; jwt.decode fails with the first set and succeeds with the second."""

    class FakeResponse:
        def json(self):
            return {"id_token": "tok", "access_token": "at"}

    class FakeJWK:
        @staticmethod
        def import_key_set(data):
            return data["set"]

    state = {"aktuelles_set": "alt"}

    def fake_get(url, **kw):
        class A:
            @staticmethod
            def json():
                return {"set": state["aktuelles_set"]}
        return A()

    def fake_decode(token, key_name, claims_options=None):
        attempts.append(key_name)
        if key_name != "neu":
            raise ValueError("bad signature: unknown kid")
        # `aud` belongs here since `exchange()` checks the audience (F-15): a token without a
        # matching `aud` is none for us, and the stand-in is to reproduce a valid one.
        return FakeClaims({"sub": "u1", "nonce": None, "aud": c.client_id})

    sys.modules["httpx"] = types.SimpleNamespace(post=lambda *a, **k: FakeResponse(), get=fake_get)
    # `exchange` builds its decoder itself (with a fixed algorithm list, see section 4) —
    # the stand-in must reproduce it, otherwise this section tests an import error.
    fake_jwt = types.SimpleNamespace(decode=fake_decode)
    sys.modules["authlib.jose"] = types.SimpleNamespace(
        JsonWebKey=FakeJWK, JsonWebToken=lambda algs: fake_jwt, jwt=fake_jwt)
    return state


c3 = fresh_client()
attempts = []
real_httpx = sys.modules.get("httpx")
real_jose = sys.modules.get("authlib.jose")
state = make_exchange_environment(c3, attempts)
try:
    c3._jwks, c3._jwks_when = "alt", time.time() - c3.JWKS_MIN_GAP - 1
    state["aktuelles_set"] = "neu"          # the provider has rotated
    claims, tok = c3.exchange("code", "https://app.example.com/cb", None)
    r.check("after a key rotation the login succeeds on the second attempt",
            claims.get("sub") == "u1", f"claims={dict(claims) if claims else None}")
    r.check("and indeed through exactly ONE re-fetch, not through guessing",
            attempts == ["alt", "neu"], f"attempts: {attempts}")

    # The throttle may close the emergency exit: freshly fetched → no second attempt.
    c4 = fresh_client()
    attempts2 = []
    make_exchange_environment(c4, attempts2)
    c4._jwks, c4._jwks_when = "alt", time.time()      # just fetched
    try:
        c4.exchange("code", "https://app.example.com/cb", None)
        slipped_through = True
    except Exception:
        slipped_through = False
    r.check("a stream of broken tokens triggers no fetch storm",
            not slipped_through and attempts2 == ["alt"],
            f"attempts: {attempts2} — the throttle does not take effect")
finally:
    if real_httpx is not None:
        sys.modules["httpx"] = real_httpx
    if real_jose is not None:
        sys.modules["authlib.jose"] = real_jose
    else:
        sys.modules.pop("authlib.jose", None)

# ---------- 4) Algorithm confusion: the token does not determine how it is verified ----------
# `authlib.jose.jwt` is a decoder WITH a default set, and that contains HS256. If no method is named
# on decoding, the **header of the token** decides how verification is done — that is, the
# sender. Up to authlib 1.3.0 this allowed forging an ID token with the public key as
# HMAC secret (GHSA-5357-c2jx-v7qh); the floor in `pyproject.toml` was at 1.3, an
# installation with a lockfile got exactly this version. The lasting bolt is not the
# version but the own list: `OIDCClient.ID_TOKEN_ALGS` (B4-1 from T-13).
import base64  # noqa: E402
import hashlib  # noqa: E402
import hmac  # noqa: E402
import json  # noqa: E402

from authlib.jose import JsonWebKey as _JWK  # noqa: E402
from authlib.jose import jwt as _default_decoder  # noqa: E402
from tinysesam import errors as _err4  # noqa: E402

r.check("the list names no symmetric method and no 'none'",
        all(a.startswith(("RS", "PS", "ES", "Ed")) for a in OIDCClient.ID_TOKEN_ALGS),
        f"ID_TOKEN_ALGS={OIDCClient.ID_TOKEN_ALGS}")

c6 = fresh_client()
try:
    c6.ID_TOKEN_ALGS = ("RS256", "HS256")
    c6._decoder()
    watched = False
except _err4.ConfigError:
    watched = True
r.check("HS256 in the list is rejected, not passed through", watched,
        "a later extension could tear the hole open again")


def _b64(raw_data: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw_data).rstrip(b"=")


def _hs256(secret: bytes, payload: dict, kid: str = "k1") -> str:
    """Build an HS256 token — what the attacker sends."""
    head = _b64(json.dumps({"alg": "HS256", "kid": kid, "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(secret, head + b"." + body, hashlib.sha256).digest())
    return (head + b"." + body + b"." + sig).decode()


def _oidc_environment(jwks_document, id_token):
    """httpx stand-in: the token endpoint returns `id_token`, the JWKS endpoint the set."""
    class Response:
        def __init__(self, payload):
            self._n = payload

        def json(self):
            return self._n

    sys.modules["httpx"] = types.SimpleNamespace(
        post=lambda *a, **k: Response({"id_token": id_token, "access_token": "at"}),
        get=lambda *a, **k: Response(jwks_document))


private = _JWK.generate_key("RSA", 2048, {"kid": "k1"}, is_private=True)
JWKS_RSA = {"keys": [private.as_dict(is_private=False)]}
PAYLOAD = {"iss": META["issuer"], "aud": "cid", "sub": "u1", "nonce": "n1",
            "iat": int(time.time()), "exp": int(time.time()) + 600}
OPTIONS = {"iss": {"essential": True, "value": META["issuer"]},
            "aud": {"essential": True, "value": "cid"}}

real_httpx4 = sys.modules.get("httpx")
try:
    # a) The legitimate path stays open: a real RS256 token goes through `exchange`.
    real = _default_decoder.encode({"alg": "RS256", "kid": "k1"}, dict(PAYLOAD), private).decode()
    c7 = fresh_client()
    _oidc_environment(JWKS_RSA, real)
    claims, _tok = c7.exchange("code", "https://app.example.com/cb", "n1")
    r.check("the legitimate path stays open: RS256 against the JWKS is accepted",
            claims.get("sub") == "u1", f"claims={dict(claims) if claims else None}")

    # b) The attack: same JWKS, but `alg: HS256` with the public key as
    #    HMAC secret. The attacker knows the JWKS — it is publicly retrievable.
    public = json.dumps(private.as_dict(is_private=False), separators=(",", ":")).encode()
    forged = _hs256(public, {**PAYLOAD, "sub": "angreifer"})
    c8 = fresh_client()
    _oidc_environment(JWKS_RSA, forged)
    try:
        c8.exchange("code", "https://app.example.com/cb", "n1")
        through = True
    except Exception:
        through = False
    r.check("an HS256 token against the RSA JWKS is rejected", not through,
            "the public key would then be the signing secret")

    # c) Precondition — and at the same time the proof that the list WORKS and does not just stand there:
    #    the same attack against a key set in which authlib's default decoder actually
    #    executes HMAC. The default accepts the token, TinySesam's decoder does not.
    #    Without the fixed list in `_decoder()` both lines would be equal — and this test red.
    secret_text = b"0123456789abcdef0123456789abcdef"
    jwks_oct = {"keys": [{"kty": "oct", "kid": "k1", "k": _b64(secret_text).decode()}]}
    tok_oct = _hs256(secret_text, {**PAYLOAD, "sub": "angreifer"})
    sentence = _JWK.import_key_set(jwks_oct)
    try:
        default = _default_decoder.decode(tok_oct, sentence, claims_options=OPTIONS)
        default.validate()
        default_took_an = default.get("sub") == "angreifer"
    except Exception:
        default_took_an = False
    r.check("precondition: authlib's default decoder accepts exactly this HS256 token",
            default_took_an,
            "without this precondition the next test measures nothing — then it would be down to authlib")

    c9 = fresh_client()
    try:
        c9._decoder().decode(tok_oct, sentence, claims_options=OPTIONS)
        own_took_an = True
    except Exception:
        own_took_an = False
    r.check("TinySesam's decoder rejects the same token", not own_took_an,
            "the algorithm list has no effect — `alg` in the header decides again")
finally:
    if real_httpx4 is not None:
        sys.modules["httpx"] = real_httpx4
    else:
        sys.modules.pop("httpx", None)


# ---------- 5) Discovery: issuer comparison, no redirect ----------
# From the discovery document come token_endpoint, jwks_uri and the issuer against which every
# ID token is verified. Up to 0.18.0 it was fetched with follow_redirects=True and never compared with
# oidc_issuer: a 3xx on the well-known path would have replaced the whole login (RB-03).
from tinysesam import errors as _errors  # noqa: E402


def discovery_client(status, document):
    calls = []

    class Response:
        status_code = status

        @staticmethod
        def json():
            return document

    def fake_get(url, **kw):
        calls.append((url, kw))
        return Response()

    sys.modules["httpx"] = types.SimpleNamespace(get=fake_get)
    return OIDCClient("https://id.example.com", "cid", "geheim", "openid"), calls


def meta_error(c):
    try:
        c.meta()
    except _errors.ConfigError as e:
        return str(e)
    return None


real_httpx5 = sys.modules.get("httpx")
try:
    c5, on = discovery_client(200, dict(META))
    r.check("matching document is accepted", meta_error(c5) is None and c5.meta()["issuer"] == META["issuer"])
    r.check("discovery is fetched WITHOUT redirect",
            on and on[0][1].get("follow_redirects") is False, f"call: {on}")

    c5b, _ = discovery_client(200, {**META, "issuer": "https://id.example.com/"})
    r.check("trailing slash on the issuer does not count as a deviation", meta_error(c5b) is None)

    c5c, _ = discovery_client(200, {**META, "issuer": "https://attacker.example"})
    f = meta_error(c5c)
    r.check("foreign issuer in the document → ConfigError, both values in the message",
            f is not None and re.search(r"attacker\.example", f) and re.search(r"oidc_issuer=https://id\.example\.com\b", f),
            f"error: {f}")

    c5d, _ = discovery_client(302, {})
    f = meta_error(c5d)
    r.check("302 on the well-known path is not followed but rejected",
            f is not None and "302" in f, f"error: {f}")

    # Precondition, so that the check above is not green by accident: without the comparison
    # the foreign document would go through — exactly that was the finding.
    c5e, _ = discovery_client(200, {**META, "issuer": "https://attacker.example"})
    c5e._check_issuer = lambda meta: None
    r.check("precondition: without the comparison the foreign document would go through", meta_error(c5e) is None)
finally:
    if real_httpx5 is not None:
        sys.modules["httpx"] = real_httpx5
    else:
        sys.modules.pop("httpx", None)

# ---------- 6) T-14: one provider, several clients ----------
# Discovery document and JWKS belong to the provider, not to the client. If every client asked
# individually, an installation with three applications would fetch the same document three times — and a
# key rotation would have to be noticed three times instead of once. The flow part (which client for
# which host) is in tests/test_forward_auth.py, where the TestClient is at home.
from tinysesam import TinySesamConfig                                    # noqa: E402
from tinysesam.oidc import OIDCClients, DEFAULT_CLIENT                   # noqa: E402

_cfg14 = TinySesamConfig(
    db_path="/dev/null", passkey_enabled=False,
    oidc_enabled=True, oidc_issuer="https://id.example.com",
    oidc_client_id="haupt", oidc_client_secret="s-haupt",
    oidc_clients={"app-a.example.com": {"client_id": "a", "client_secret": "s-a"},
                  "app-b.example.com": {"client_id": "b", "client_secret": "s-b",
                                        "scopes": "openid profile email groups"}})
_reg = OIDCClients(_cfg14)
_reg[DEFAULT_CLIENT]._meta, _reg[DEFAULT_CLIENT]._meta_when = dict(META), time.time()
_reg._parts_meta()

r.check("each application has its own client at the same provider",
        [_reg.for_host(h).client_id for h in ("app-a.example.com", "app-b.example.com")] == ["a", "b"])
r.check("an unknown host gets the default client, the flow does not abort",
        _reg.for_host("fremd.example.com").client_id == "haupt")
r.check("the port is not part of the application name",
        _reg.for_host("app-b.example.com:8443").client_id == "b")
r.check("an own scope per application is adopted",
        "groups" in _reg["app-b.example.com"].scopes
        and _reg["app-a.example.com"].scopes == _cfg14.oidc_scopes)
r.check("all clients share the metadata of the one provider",
        all(_reg[k]._meta is _reg[DEFAULT_CLIENT]._meta for k in _reg.names()))
r.check("and the same issuer — a second provider is not intended",
        {_reg[k].issuer for k in _reg.names()} == {"https://id.example.com"})

# ---------- 7) F-15: aud and azp according to OIDC Core 3.1.3.7 ----------
# The decoder only checks that the own client_id OCCURS in `aud`. A token may name several
# recipients — then only `azp` says who it was made for. Without this check TinySesam
# accepts a token issued for ANOTHER application of the same provider
# that merely names us as well (token substitution). Since T-14 this weighs double: with several clients
# of the same installation the token of app A would also be good for app B.
from fastapi import HTTPException as _HTTPException                      # noqa: E402

_c15 = fresh_client()


def _audience_error(**claims):
    try:
        _c15._check_audience(FakeClaims(claims), lambda k, **f: k)
        return None
    except _HTTPException as e:
        return e.detail


r.check("a token only for us goes through", _audience_error(aud="cid") is None)
r.check("several recipients WITH matching azp go through",
        _audience_error(aud=["cid", "andere"], azp="cid") is None)
r.check("several recipients WITHOUT azp are rejected",
        _audience_error(aud=["cid", "andere"]) == "api.oidc_audience")
r.check("a foreign azp is rejected, even if we are in aud",
        _audience_error(aud=["cid", "andere"], azp="andere") == "api.oidc_audience")
r.check("a token entirely without us is rejected",
        _audience_error(aud=["andere"]) == "api.oidc_audience")
r.check("a token without aud is rejected", _audience_error() == "api.oidc_audience")
r.check("a single foreign azp alone suffices for rejection",
        _audience_error(aud="cid", azp="andere") == "api.oidc_audience")

# ---------- 8) F-18: the UserInfo response must match the ID token ----------
# The response is NOT signed and is laid over the claims in the callback — it supplies
# groups, email and thus indirectly roles and the admin flag. OIDC Core 5.3.2 explicitly
# requires the comparison of `sub`.
_c18 = fresh_client()
_real_httpx18 = sys.modules.get("httpx")


def _userinfo_with(response, expected):
    class A:
        @staticmethod
        def json():
            return response
    sys.modules["httpx"] = types.SimpleNamespace(get=lambda *a, **k: A())
    try:
        return _c18.userinfo("at", expected_sub=expected)
    finally:
        if _real_httpx18 is not None:
            sys.modules["httpx"] = _real_httpx18
        else:
            sys.modules.pop("httpx", None)


_c18._meta = {**META, "userinfo_endpoint": "https://id.example.com/userinfo"}
_c18._meta_when = time.time()
r.check("matching sub → the response is used",
        _userinfo_with({"sub": "u1", "groups": ["a"]}, "u1").get("groups") == ["a"])
r.check("foreign sub → the response is discarded, not partly adopted",
        _userinfo_with({"sub": "u2", "groups": ["admins"], "email": "wer@example.com"}, "u1") == {})
r.check("response without sub → discarded (fail-closed instead of partly adopting)",
        _userinfo_with({"groups": ["admins"]}, "u1") == {})
r.check("without an expected sub the caller gets nothing",
        _userinfo_with({"sub": "u1", "groups": ["a"]}, "") == {})
r.check("a response that is not an object is discarded",
        _userinfo_with(["kein", "objekt"], "u1") == {})

# ---------- 9) F-20/H-12: PKCE with S256 ----------
# Without PKCE an intercepted authorization code (referer, proxy log, browser history) was
# redeemable as long as the attacker also has the client secret — or injectable into a foreign flow.
# The verifier stays in the flow record; only the challenge travels through the browser.
from urllib.parse import parse_qs as _pqs, urlparse as _up  # noqa: E402
from tinysesam.oidc import pkce_pair  # noqa: E402

_v, _ch = pkce_pair()
_expected = base64.urlsafe_b64encode(hashlib.sha256(_v.encode()).digest()).rstrip(b"=").decode()
r.check("pkce_pair: challenge = BASE64URL(SHA256(verifier)) without padding (RFC 7636 4.2)",
        _ch == _expected and "=" not in _ch, f"{_ch} ≠ {_expected}")
r.check("pkce_pair: verifier 43–128 characters from the permitted alphabet",
        43 <= len(_v) <= 128 and re.fullmatch(r"[A-Za-z0-9\-._~]+", _v) is not None, _v)
r.check("pkce_pair: every call a new pair", pkce_pair()[0] != _v)
_q = _pqs(_up(fresh_client().auth_url("https://app.example.com/cb", "st", "no",
                                         code_challenge=_ch)).query)
r.check("auth_url carries code_challenge and code_challenge_method=S256",
        _q.get("code_challenge") == [_ch] and _q.get("code_challenge_method") == ["S256"], _q)

_posts = []


def _pkce_environment(id_token):
    class A:
        def __init__(self, n):
            self._n = n

        def json(self):
            return self._n

    def _post(url, **kw):
        _posts.append(kw.get("data") or {})
        return A({"id_token": id_token, "access_token": "at"})

    sys.modules["httpx"] = types.SimpleNamespace(post=_post, get=lambda *a, **k: A(JWKS_RSA))


real_httpx9 = sys.modules.get("httpx")
try:
    _tok9 = _default_decoder.encode({"alg": "RS256", "kid": "k1"}, dict(PAYLOAD), private).decode()
    _pkce_environment(_tok9)
    fresh_client().exchange("code", "https://app.example.com/cb", "n1", code_verifier=_v)
    r.check("exchange sends the code_verifier to the token endpoint",
            _posts and _posts[-1].get("code_verifier") == _v, _posts)

    # ---------- 10) F-25: an ID token without `exp` does not hold forever ----------
    def _swap(payload):
        tok = _default_decoder.encode({"alg": "RS256", "kid": "k1"}, payload, private).decode()
        _pkce_environment(tok)
        try:
            fresh_client().exchange("code", "https://app.example.com/cb", "n1")
            return None
        except Exception as e:           # noqa: BLE001 — every rejection counts as "no" here
            return type(e).__name__

    _without_exp = {k: v for k, v in PAYLOAD.items() if k != "exp"}
    r.check("F-25: an ID token WITHOUT exp is rejected", _swap(_without_exp) is not None,
            "authlib checks exp only if the claim is present — the token would hold forever")
    r.check("F-25: control — with exp the same token goes through", _swap(dict(PAYLOAD)) is None)

    # ---------- 11) F-26: a few seconds of clock skew at the provider do not block a login ----------
    _t = int(time.time())
    r.check("F-26: iat 30 s in the future (provider clock runs ahead) is accepted",
            _swap({**PAYLOAD, "iat": _t + 30, "nbf": _t + 30}) is None,
            "without leeway every login fails as soon as the IdP's clock runs ahead")
    r.check("F-26: …but the tolerance is limited: iat far in the future stays rejected",
            _swap({**PAYLOAD, "iat": _t + 3600, "nbf": _t + 3600}) is not None)
    r.check("F-26: an expired token (exp beyond the tolerance) stays rejected",
            _swap({**PAYLOAD, "iat": _t - 600, "exp": _t - OIDCClient.CLOCK_TOLERANCE - 30}) is not None)
finally:
    if real_httpx9 is not None:
        sys.modules["httpx"] = real_httpx9
    else:
        sys.modules.pop("httpx", None)

# ---------- 12) F-24: an error response of the provider is not cached ----------
# Discovery: since F-13 (#55) a non-200 or a foreign issuer raises BEFORE `_meta` is set.
# What is measured here is that it is really asked anew afterwards — otherwise a maintenance window
# of the provider would be an outage here for 24 hours.
real_httpx12 = sys.modules.get("httpx")
try:
    _sequence = [(503, {"error": "wartung"}), (200, {"error": "server_error"}), (200, dict(META))]
    _fetches12 = []

    def _get12(url, **kw):
        status, doc = _sequence[min(len(_fetches12), len(_sequence) - 1)]
        _fetches12.append(url)
        return types.SimpleNamespace(status_code=status, json=lambda d=doc: d)

    sys.modules["httpx"] = types.SimpleNamespace(get=_get12)
    c12 = OIDCClient("https://id.example.com", "cid", "geheim", "openid")
    _f1, _f2 = meta_error(c12), meta_error(c12)
    r.check("F-24: 503 and a 200 with an error document are rejected and NOT remembered",
            _f1 is not None and _f2 is not None and c12._meta is None and len(_fetches12) == 2,
            f"_meta={c12._meta!r}, fetches={len(_fetches12)}")
    r.check("F-24: the next fetch after the end of the disruption gets the real document",
            meta_error(c12) is None and c12.meta()["issuer"] == META["issuer"] and len(_fetches12) == 3)

    # JWKS: an error response (here 500 with an empty set) does not get into the cache.
    _jwks_sequence = [(500, {"keys": []}), (200, JWKS_RSA)]
    _jwks_fetches = []

    def _get12b(url, **kw):
        status, doc = _jwks_sequence[min(len(_jwks_fetches), 1)]
        _jwks_fetches.append(url)
        return types.SimpleNamespace(status_code=status, json=lambda d=doc: d)

    sys.modules["httpx"] = types.SimpleNamespace(get=_get12b)
    c12b = fresh_client()
    try:
        c12b._jwkset()
        _jwks_error = None
    except _errors.ConfigError as e:
        _jwks_error = str(e)
    r.check("F-24: JWKS with 500 is rejected and not remembered",
            _jwks_error is not None and "500" in _jwks_error and c12b._jwks is None,
            f"error={_jwks_error!r}, cache={c12b._jwks!r}")
    r.check("F-24: …the next fetch gets the real set", c12b._jwkset() is not None
            and len(_jwks_fetches) == 2)
finally:
    if real_httpx12 is not None:
        sys.modules["httpx"] = real_httpx12
    else:
        sys.modules.pop("httpx", None)

sys.exit(r.done())

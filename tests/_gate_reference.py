"""Reference gate client: the checking rules of `spec/gate-client.md`, in Python, for `tests/test_gate_vectors.py`.

TinySesam itself has no application-side verifier: `tinysesam.gate.check` checks a token the way the proxy does
(one fixed key, no JWKS, no `Remote-*` headers). This module is the executable reading of the specification that
the language-neutral vectors in `spec/vectors/` are checked against — the Go, Rust, JS and PHP clients have to reach
the same verdicts. It is test code, not part of the package — yet: the Python gate client `tinysesam.gate_client`
(T-86) grows out of it, so it stays free of FastAPI and of TinySesam's internals (standard library and
`cryptography` only) and keeps its rules in plain functions. The `relax` switches stay behind in the tests.

`relax` switches off one rule at a time. The vector suite uses it as a self-probe: every relaxation must turn at
least one vector red, otherwise the vectors do not measure that rule.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

MAX_TOKEN_BYTES = 4096
MAX_LEEWAY = 60
MAX_LIFETIME = 3600
MAX_SAFE_INTEGER = 2 ** 53 - 1
ALGORITHM = "EdDSA"
TOKEN_TYPE = "tinysesam-gate+jwt"
HEADER_MEMBERS = frozenset({"alg", "typ", "kid"})
IDENTITY_CLAIMS = ("ts_user", "ts_name", "ts_email", "ts_groups", "ts_id", "ts_auth")
AUTH_KINDS = ("session", "oauth", "apikey", "app-password")
REMOTE_HEADERS = ("Remote-User", "Remote-Name", "Remote-Email", "Remote-Groups", "Remote-Id", "Remote-Auth")

#: JWKS cache parameters (spec section "Fetching the key set").
JWKS_DEFAULT_FRESH = 300
JWKS_MIN_FRESH = 60
JWKS_MAX_FRESH = 3600
JWKS_STALE_MAX = 3600
JWKS_MIN_INTERVAL = 10
JWKS_MAX_KEYS = 32

ERRORS = ("malformed", "header", "kid", "signature", "claims", "issuer", "audience", "lifetime", "not_yet_valid",
          "expired", "key_unavailable")
HEADER_ERRORS = ("unauthenticated", "header")

#: Every rule a self-probe may switch off.
#: Each switches off one check (two only where they are one defect, such as the length and the verification of the
#: signature); `tests/test_gate_vectors.py` also uses them to show that every attack vector carries one defect.
RELAXATIONS = ("alg_from_header", "ignore_typ", "embedded_jwk", "unknown_header_members", "no_duplicate_check",
               "lenient_base64", "lenient_utf8", "allow_bom", "allow_nan", "no_size_limit", "skip_signature",
               "no_exp", "no_nbf", "no_lifetime", "no_control_check", "no_ts_id_check", "allow_empty_sub",
               "aud_casefold", "iss_prefix", "kid_any_format", "claim_types_loose", "jwks_any_entry",
               "jwks_no_interval", "jwks_no_stale_limit", "header_strip_control", "header_first_value",
               "header_lenient_utf8", "header_any_id", "remote_auth_empty_is_session", "groups_no_trim",
               "topbar_any_href")

_KID = re.compile(r"[0-9a-f]{16}")
_SEGMENT = re.compile(r"[A-Za-z0-9_-]*")
_DIGITS = re.compile(r"[0-9]+")
_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*([0-9]+)\s*(?:,|$)", re.IGNORECASE)


class GateError(Exception):
    """A rejection. `kind` is the error class of the specification."""

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(segment: str, relax=frozenset()) -> bytes:
    """Strict base64url: URL-safe alphabet, no padding, no whitespace, canonical (the unused bits are zero)."""
    if "lenient_base64" in relax:
        try:
            bare = "".join(segment.split()).replace("=", "")
            return base64.urlsafe_b64decode(bare + "=" * (-len(bare) % 4))
        except (ValueError, TypeError) as e:
            raise GateError("malformed", "base64") from e
    if not _SEGMENT.fullmatch(segment) or len(segment) % 4 == 1:
        raise GateError("malformed", "base64 alphabet or length")
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if b64u_encode(raw) != segment:
        raise GateError("malformed", "base64 not canonical")
    return raw


def _no_constant(name):
    raise GateError("malformed", f"JSON constant {name}")


def json_object(raw: bytes, relax=frozenset()) -> dict:
    """A JSON object from UTF-8 bytes: no BOM, no duplicate member names, no NaN/Infinity."""
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out and "no_duplicate_check" not in relax:
                raise GateError("malformed", f"duplicate member {k!r}")
            out[k] = v
        return out
    try:
        text = raw.decode("utf-8", "replace" if "lenient_utf8" in relax else "strict")
    except UnicodeDecodeError as e:
        raise GateError("malformed", "not UTF-8") from e
    if text.startswith("\ufeff"):
        if "allow_bom" not in relax:
            raise GateError("malformed", "byte order mark")
        text = text[1:]
    try:
        value = json.loads(text, object_pairs_hook=pairs,
                           parse_constant=float if "allow_nan" in relax else _no_constant)
    except ValueError as e:
        raise GateError("malformed", "not JSON") from e
    if not isinstance(value, dict):
        raise GateError("malformed", "not a JSON object")
    return value


def has_control(text: str) -> bool:
    """C0 control characters and DEL — exactly what TinySesam removes from header values and claims."""
    return any(c < " " or c == "\x7f" for c in text)


def key_id(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()[:16]


# ---------- the key set ----------

def jwk_entry(entry, relax=frozenset()):
    """(kid, 32 public bytes) of a usable JWKS entry, None for an entry that must be skipped."""
    if not isinstance(entry, dict):
        return None
    if "jwks_any_entry" in relax:
        try:
            return str(entry.get("kid")), b64u_decode(str(entry.get("x")), frozenset({"lenient_base64"}))
        except GateError:
            return None
    if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
        return None
    if any(m in entry for m in ("d", "x5u", "x5c", "x5t", "x5t#S256", "jku")):
        return None
    if "alg" in entry and entry["alg"] != ALGORITHM:
        return None
    if "use" in entry and entry["use"] != "sig":
        return None
    if "key_ops" in entry and not (isinstance(entry["key_ops"], list) and "verify" in entry["key_ops"]):
        return None
    x, kid = entry.get("x"), entry.get("kid")
    if not isinstance(x, str) or not isinstance(kid, str):
        return None
    try:
        public = b64u_decode(x)
    except GateError:
        return None
    if len(public) != 32 or kid != key_id(public):
        return None
    return kid, public


def parse_jwks(doc, relax=frozenset()) -> dict:
    """kid → public key of every usable entry. A document of the wrong shape raises `jwks_invalid`."""
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list) or len(doc["keys"]) > JWKS_MAX_KEYS:
        raise GateError("jwks_invalid", "shape")
    found = [jwk_entry(e, relax) for e in doc["keys"]]
    kids = [f[0] for f in found if f]
    return {kid: public for kid, public in (f for f in found if f) if kids.count(kid) == 1}


# ---------- the token ----------

def parse(jws, relax=frozenset()):
    """Steps 1–5 (spec "Checking order"): everything that is decided before a key is chosen."""
    if not isinstance(jws, str):
        raise GateError("malformed", "not a string")
    if "no_size_limit" not in relax and len(jws.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise GateError("malformed", "too large")
    parts = jws.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        raise GateError("malformed", "not three segments")
    h_seg, p_seg, s_seg = parts
    head_raw, payload_raw, sig = (b64u_decode(p, relax) for p in parts)
    head = json_object(head_raw, relax)
    extra = set(head) - HEADER_MEMBERS
    if "embedded_jwk" in relax:
        extra -= {"jwk"}
    if extra and "unknown_header_members" not in relax and "embedded_jwk" not in relax:
        raise GateError("header", f"member(s) {sorted(extra)}")
    alg = head.get("alg")
    if "alg_from_header" not in relax and not (isinstance(alg, str) and alg == ALGORITHM):
        raise GateError("header", "alg")
    typ = head.get("typ")
    if "ignore_typ" not in relax and not (isinstance(typ, str) and typ.isascii() and typ.lower() == TOKEN_TYPE):
        raise GateError("header", "typ")
    kid = head.get("kid")
    if not isinstance(kid, str) or ("kid_any_format" not in relax and not _KID.fullmatch(kid)):
        raise GateError("kid", "missing or not 16 lowercase hex digits")
    if _header_alg(head, relax) == ALGORITHM and len(sig) != 64 and "skip_signature" not in relax:
        raise GateError("signature", "not 64 bytes")
    return {"signing_input": f"{h_seg}.{p_seg}".encode("ascii"), "head": head, "payload": payload_raw,
            "sig": sig, "kid": kid}


def _header_alg(head, relax) -> str:
    """The algorithm to verify with: the constant, or — relaxed — what the header names (`none`, `HS256` in any
    spelling; anything else counts as Ed25519)."""
    alg = head.get("alg")
    if "alg_from_header" in relax and isinstance(alg, str) and alg.lower() in ("none", "hs256"):
        return alg.lower()
    return ALGORITHM


def _check_signature(parsed, public: bytes, relax) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    head, sig, data = parsed["head"], parsed["sig"], parsed["signing_input"]
    if "embedded_jwk" in relax and isinstance(head.get("jwk"), dict):
        public = b64u_decode(str(head["jwk"].get("x")), frozenset({"lenient_base64"}))
    if "skip_signature" in relax or _header_alg(head, relax) == "none":
        return
    if _header_alg(head, relax) == "hs256":
        for secret in (public, base64.b64encode(public)):
            if hmac.compare_digest(hmac.new(secret, data, hashlib.sha256).digest(), sig):
                return
        raise GateError("signature", "HMAC")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, data)
    except (InvalidSignature, ValueError) as e:
        raise GateError("signature", "Ed25519") from e


def _is_int(v, relax) -> bool:
    if "claim_types_loose" in relax:
        try:
            int(v)
            return True
        except (TypeError, ValueError):
            return False
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_SAFE_INTEGER


def _check_claims(claims: dict, *, issuer, audience, now, leeway, relax) -> None:
    """Steps 9–10: types and consistency, then issuer, audience, lifetime, nbf, exp."""
    loose = "claim_types_loose" in relax
    for name in ("iss", "sub"):
        if not isinstance(claims.get(name), str) and not loose:
            raise GateError("claims", name)
    aud = claims.get("aud")
    if not loose and not (isinstance(aud, str) or (isinstance(aud, list) and aud and all(isinstance(a, str) for a in aud))):
        raise GateError("claims", "aud")
    for name in ("iat", "nbf", "exp"):
        if not _is_int(claims.get(name), relax):
            raise GateError("claims", name)
    if "jti" in claims and not isinstance(claims["jti"], str) and not loose:
        raise GateError("claims", "jti")
    for name in IDENTITY_CLAIMS:
        if name in claims:
            if not isinstance(claims[name], str) and not loose:
                raise GateError("claims", name)
            if "no_control_check" not in relax and has_control(str(claims[name])):
                raise GateError("claims", f"control character in {name}")
    sub = str(claims.get("sub"))
    if (not sub and "allow_empty_sub" not in relax) or ("no_control_check" not in relax and has_control(sub)):
        raise GateError("claims", "sub")
    if "ts_id" in claims and claims["ts_id"] != claims.get("sub") and "no_ts_id_check" not in relax:
        raise GateError("claims", "ts_id differs from sub")
    if int(claims["iat"]) > int(claims["nbf"]) and not loose:
        raise GateError("claims", "iat later than nbf")
    iss = claims.get("iss")
    if not (iss == issuer or ("iss_prefix" in relax and str(iss).startswith(issuer))):
        raise GateError("issuer")
    targets = aud if isinstance(aud, list) else [aud]
    if "aud_casefold" in relax:
        hit = any(str(a).lower() == audience.lower() for a in targets)
    else:
        hit = audience in targets
    if not hit:
        raise GateError("audience")
    nbf, exp = int(claims["nbf"]), int(claims["exp"])
    if "no_lifetime" not in relax and (exp <= nbf or exp - nbf > MAX_LIFETIME):
        raise GateError("lifetime")
    if "no_nbf" not in relax and nbf > now + leeway:
        raise GateError("not_yet_valid")
    if "no_exp" not in relax and exp + leeway <= now:
        raise GateError("expired")


def check_leeway(leeway) -> int:
    if not isinstance(leeway, int) or isinstance(leeway, bool) or not 0 <= leeway <= MAX_LEEWAY:
        raise ValueError(f"clock leeway must be an integer from 0 to {MAX_LEEWAY} seconds")
    return leeway


def verify(jws, *, keys: dict, issuer: str, audience: str, now: int, leeway: int = 0, relax=frozenset()) -> dict:
    """The claims of a valid token; `GateError` with the class of the first failing step otherwise."""
    check_leeway(leeway)
    parsed = parse(jws, relax)
    public = keys.get(parsed["kid"])
    if public is None and not ("embedded_jwk" in relax and "jwk" in parsed["head"]):
        raise GateError("kid", "unknown")
    return finish(parsed, public, issuer=issuer, audience=audience, now=now, leeway=leeway, relax=relax)


def finish(parsed, public, *, issuer, audience, now, leeway, relax=frozenset()) -> dict:
    _check_signature(parsed, public, relax)
    claims = json_object(parsed["payload"], relax)
    _check_claims(claims, issuer=issuer, audience=audience, now=now, leeway=leeway, relax=relax)
    return claims


# ---------- identity ----------

def parse_groups(text: str, relax=frozenset()) -> list:
    """`Remote-Groups` / `ts_groups`: split at every comma, trim spaces, drop empty entries and repeats."""
    out = []
    for part in text.split(","):
        g = part if "groups_no_trim" in relax else part.strip(" ")
        if g and g not in out:
            out.append(g)
    return out


def identity_from_claims(claims: dict, relax=frozenset()) -> dict:
    auth = claims.get("ts_auth", "")
    return {"user": claims.get("ts_user", ""), "name": claims.get("ts_name", ""),
            "email": claims.get("ts_email", ""), "groups": parse_groups(str(claims.get("ts_groups", "")), relax),
            "id": claims["sub"], "auth": auth if auth in AUTH_KINDS else "",
            "kind": "session" if auth == "session" else "token"}


def identity_from_headers(headers: dict, relax=frozenset()) -> dict:
    """Header mode. `headers` maps a field name to its value (a string of octets U+0000–U+00FF) or to a list of
    values when the field occurred more than once."""
    seen = {}
    for name, value in headers.items():
        key = name.lower()
        if key in seen:
            if "header_first_value" in relax:
                continue
            raise GateError("header", f"{name} more than once")
        seen[key] = value
    values = {}
    for name in REMOTE_HEADERS:
        v = seen.get(name.lower())
        if v is None:
            continue
        if isinstance(v, list):
            if len(v) != 1 and "header_first_value" not in relax:
                raise GateError("header", f"{name} more than once")
            v = v[0]
        try:
            text = v.encode("latin-1").decode("utf-8", "replace" if "header_lenient_utf8" in relax else "strict")
        except UnicodeError as e:
            raise GateError("header", f"{name} is not UTF-8") from e
        if has_control(text):
            if "header_strip_control" not in relax:
                raise GateError("header", f"control character in {name}")
            text = "".join(c for c in text if not has_control(c))
        values[name] = text
    user = values.get("Remote-User", "")
    if not user:
        raise GateError("unauthenticated")
    rid = values.get("Remote-Id", "")
    if rid and not _DIGITS.fullmatch(rid) and "header_any_id" not in relax:
        raise GateError("header", "Remote-Id")
    auth = values.get("Remote-Auth", "")
    session = auth == "session" or ("remote_auth_empty_is_session" in relax and not auth)
    return {"user": user, "name": values.get("Remote-Name", ""), "email": values.get("Remote-Email", ""),
            "groups": parse_groups(values.get("Remote-Groups", ""), relax), "id": rid,
            "auth": auth if auth in AUTH_KINDS else "", "kind": "session" if session else "token"}


def has_role(identity: dict, role: str) -> bool:
    return role in identity["groups"]


# ---------- the JWKS cache ----------

class JwksCache:
    """The fetch-and-cache rules of the specification against a fake fetcher (`fetch(now) -> response`)."""

    def __init__(self, fetch, relax=frozenset()):
        self.fetch, self.relax = fetch, relax
        self.keys = None
        self.fresh_until = None
        self.last_attempt = None

    def _interpret(self, resp):
        if not isinstance(resp, dict) or "error" in resp or resp.get("status") != 200:
            return None
        try:
            doc = resp["body"] if "body" in resp else json_object(str(resp.get("body_text", "")).encode("utf-8"))
            keys = parse_jwks(doc, self.relax)
        except GateError:
            return None
        if not keys:
            return None
        m = _MAX_AGE.search(str(resp.get("cache_control") or ""))
        fresh = int(m.group(1)) if m else JWKS_DEFAULT_FRESH
        return keys, min(max(fresh, JWKS_MIN_FRESH), JWKS_MAX_FRESH)

    def _maybe_fetch(self, now) -> bool:
        if (self.last_attempt is not None and now - self.last_attempt < JWKS_MIN_INTERVAL
                and "jwks_no_interval" not in self.relax):
            return False
        self.last_attempt = now
        got = self._interpret(self.fetch(now))
        if got:
            self.keys, fresh = got
            self.fresh_until = now + fresh
        return True

    def lookup(self, kid: str, now: int) -> bytes:
        fetched = False
        if self.keys is None or now >= self.fresh_until:
            fetched = self._maybe_fetch(now)
        if self.keys is None or (now >= self.fresh_until + JWKS_STALE_MAX and "jwks_no_stale_limit" not in self.relax):
            raise GateError("key_unavailable")
        if kid not in self.keys and not fetched:
            self._maybe_fetch(now)
        if kid not in self.keys:
            raise GateError("kid", "unknown")
        return self.keys[kid]

    def verify(self, jws, *, issuer, audience, now, leeway=0) -> dict:
        check_leeway(leeway)
        parsed = parse(jws, self.relax)
        public = self.lookup(parsed["kid"], now)
        return finish(parsed, public, issuer=issuer, audience=audience, now=now, leeway=leeway, relax=self.relax)


# ---------- the top bar ----------

def safe_href(href, relax=frozenset()) -> bool:
    if not isinstance(href, str):
        return False
    if "topbar_any_href" in relax:
        return True
    if has_control(href) or any(c.isspace() for c in href):
        return False
    low = href.lower()
    if low.startswith(("https://", "http://")):
        return True
    return href.startswith("/") and not href.startswith(("//", "/\\"))


def topbar(data, relax=frozenset()) -> dict:
    """The top bar data reduced to what an application may render; signed out on any doubt."""
    out = {"brand": "", "signed_in": False, "name": None, "links": [], "account": None, "admin_panel": None,
           "logout": None}
    if not isinstance(data, dict):
        return out
    if isinstance(data.get("brand"), str):
        out["brand"] = data["brand"]
    if data.get("signed_in") is not True or not isinstance(data.get("name"), str):
        return out
    out["signed_in"], out["name"] = True, data["name"]
    for link in data.get("links") if isinstance(data.get("links"), list) else []:
        if isinstance(link, dict) and isinstance(link.get("title"), str) and safe_href(link.get("href"), relax):
            out["links"].append({"title": link["title"], "href": link["href"]})
    for slot in ("account", "admin_panel"):
        entry = data.get(slot)
        if isinstance(entry, dict) and entry.get("shown") is True and safe_href(entry.get("href"), relax):
            out[slot] = entry["href"]
    logout = data.get("logout")
    if isinstance(logout, dict) and safe_href(logout.get("href"), relax):
        out["logout"] = logout["href"]
    return out

"""OAuth for services — `client_credentials` with `private_key_jwt` (T-60, ADR-13).

A service or daemon without a person gets short-lived access tokens from the authorization server of ADR-11. It
is registered once with a **pairing code** (issued from an interactive session on the account page or in the
admin panel): the service creates its key pair itself and sends only the public key, together with a proof that
it holds the private one. From then on every token request carries a **client assertion** (RFC 7523 §2.2) signed
with that key. The database holds nothing that signs; a copied database or proxy log yields no token.

The rules and their sources are in `backlog/ADR-13-oauth-for-services-private-key-jwt.md`. In short:

* **Assertion** (RFC 7523 §3, RFC 10070 — formerly draft-ietf-oauth-rfc7523bis): `iss` = `sub` = client ID;
  `aud` = the issuer identifier as its SOLE value (the token endpoint URL is refused — audience injection);
  `exp` required and at most `MAX_ASSERTION_LIFETIME` ahead; `jti` single use until `exp`; `typ`, if present,
  `client-authentication+jwt` (or plain `JWT`) — never another kind of JWT.
* **Algorithms**: `Ed25519` (RFC 9864), `ES256`, and `EdDSA` for an Ed25519 key (deprecated name, still what many
  libraries send) — each only for the key type it belongs to. Never `none`, never HMAC: the key is the stored
  public key, chosen by the client ID; `jwk`, `jku`, `x5u`, `x5c` in the header are never consulted.
* **Signatures** are checked by joserfc (extra `[services]`) — no own cryptography.
* **Keys** have a lifetime (`oauth_service_key_days`); the client rotates them itself (the new key proves possession,
  the request is signed with the old one), the old key stays valid for `KEY_OVERLAP_SEC`.
* **Tokens** are the opaque access tokens of ADR-11, short-lived, without refresh token, bound to one resource;
  forward auth reads account, service and roles on every request and never sets the admin flag.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import warnings
from typing import Optional

from .oauth import ACCESS_PREFIX, DEFAULT_SCOPE, MAX_NAME_LEN, OAuthError, _detail, new_token, normalize_resource
# The one-time code is shared with the pairing consent of people's programs (ADR-14): one format, one digest.
from .oauth import CODE_ALPHABET, CODE_LEN, code_digest, new_pairing_code, normalize_code  # noqa: F401
from .store import now as _now

#: RFC 7523 §2.2.
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
#: RFC 10070 (rfc7523bis) §4: explicit type of a client authentication JWT. `JWT` and no `typ` are accepted too.
ASSERTION_TYP = "client-authentication+jwt"
#: The proofs of possession TinySesam asks for itself — a type of their own, so no other JWT passes as one.
PAIRING_TYP = "tinysesam-pairing+jwt"
KEY_TYP = "tinysesam-key+jwt"

#: Algorithm → (key type, curve). The header's `alg` must be one of these AND belong to the stored key.
ALGORITHMS = {"Ed25519": ("OKP", "Ed25519"), "EdDSA": ("OKP", "Ed25519"), "ES256": ("EC", "P-256")}

#: An assertion may be valid at most this long (its `jti` is kept until `exp`); clocks may differ by `CLOCK_SKEW`.
MAX_ASSERTION_LIFETIME = 300
CLOCK_SKEW = 30
MAX_JWT_LEN = 4096
#: After a rotation the previous key is still accepted this long — other processes of the service that still hold
#: it, and assertions already in flight.
KEY_OVERLAP_SEC = 3600
#: Keys a service may hold at once (current + those within their overlap).
MAX_KEYS = 3
#: Pairing attempts per address (an IPv6 address counts as its /64) and hour.
PAIR_PER_IP_HOUR = 20
CLIENT_PREFIX = "tss_"

_B64U = re.compile(r"[A-Za-z0-9_-]+")
_JTI = re.compile(r"[\x21-\x7e]{8,200}")


# ---------- pairing code ----------

def code_binding(code: str) -> str:
    """The value the pairing proof carries as `nonce`: binds the proof to this one code."""
    return base64.urlsafe_b64encode(hashlib.sha256(code.encode("ascii")).digest()).decode("ascii").rstrip("=")


# ---------- keys and JWS (joserfc) ----------

def _lib():
    try:
        from joserfc import jws
        from joserfc.jwk import ECKey, OKPKey
    except ImportError as e:      # pragma: no cover - the constructor refuses the switch without the extra
        raise OAuthError("server_error", "the extra [services] (joserfc) is not installed", 500) from e
    return jws, OKPKey, ECKey


def public_jwk(raw) -> tuple[dict, str]:
    """(canonical public JWK, RFC 7638 thumbprint) of a key a client sends — or `OAuthError`.

    Only OKP/Ed25519 and EC/P-256, only the public members; a JWK with a private part (`d`) or any other key type is
    refused rather than stripped — a client that sends its private key has a bug worth hearing about."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raise OAuthError("invalid_request", "jwk is no JSON") from None
    if not isinstance(raw, dict):
        raise OAuthError("invalid_request", "jwk must be a JSON object")
    if any(k in raw for k in ("d", "p", "q", "dp", "dq", "qi", "k", "oth")):
        raise OAuthError("invalid_request", "jwk must be a public key — never send the private part")
    kty, crv = raw.get("kty"), raw.get("crv")
    members: tuple
    if (kty, crv) == ("OKP", "Ed25519"):
        members = ("x",)
    elif (kty, crv) == ("EC", "P-256"):
        members = ("x", "y")
    else:
        raise OAuthError("invalid_request", "jwk: only OKP/Ed25519 or EC/P-256")
    jwk = {"kty": kty, "crv": crv}
    for m in members:
        v = raw.get(m)
        if not isinstance(v, str) or not _B64U.fullmatch(v) or len(v) != 43:
            raise OAuthError("invalid_request", f"jwk: {m} must be 32 bytes in Base64url")
        jwk[m] = v
    jws, OKPKey, ECKey = _lib()
    try:
        key = (OKPKey if kty == "OKP" else ECKey).import_key(jwk)     # an EC point off the curve fails here
    except Exception:
        raise OAuthError("invalid_request", "jwk is no valid public key") from None
    return jwk, key.thumbprint()


def _segments(token) -> tuple[dict, dict]:
    """(header, claims) of a compact JWS WITHOUT checking it — only to find the key. Never trusted on its own."""
    if not isinstance(token, str) or not token or len(token) > MAX_JWT_LEN:
        raise OAuthError("invalid_client", "malformed assertion")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts) or not all(_B64U.fullmatch(p) for p in parts):
        raise OAuthError("invalid_client", "malformed assertion")
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        raise OAuthError("invalid_client", "malformed assertion") from None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise OAuthError("invalid_client", "malformed assertion")
    return header, claims


def _typ_ok(header: dict, wanted: str, plain_ok: bool) -> bool:
    typ = header.get("typ")
    if typ is None:
        return plain_ok
    if not isinstance(typ, str):
        return False
    t = typ.lower()
    if t.startswith("application/"):
        t = t[len("application/"):]
    return t == wanted or (plain_ok and t == "jwt")


def verify(token: str, jwk: dict, *, typ: str, plain_ok: bool, error: str = "invalid_client") -> tuple[dict, dict]:
    """(header, claims) of a JWS signed with `jwk` — or `OAuthError(error)`.

    The algorithm comes from the header but must be on the list AND belong to the key's type; joserfc checks the
    signature with exactly that one algorithm. `crit` with anything unknown is refused by joserfc."""
    header, _ = _segments(token)
    alg = header.get("alg")
    if not isinstance(alg, str) or ALGORITHMS.get(alg) != (jwk.get("kty"), jwk.get("crv")):
        raise OAuthError(error, "algorithm not allowed for this key")
    if not _typ_ok(header, typ, plain_ok):
        raise OAuthError(error, "wrong JWT type")
    jws, OKPKey, ECKey = _lib()
    try:
        key = (OKPKey if jwk["kty"] == "OKP" else ECKey).import_key(jwk)
        with warnings.catch_warnings():
            # joserfc warns on `EdDSA` (deprecated by RFC 9864) — accepted on purpose for older clients.
            warnings.simplefilter("ignore")
            obj = jws.deserialize_compact(token, key, algorithms=[alg])
        claims = json.loads(obj.payload)
    except Exception:
        raise OAuthError(error, "signature invalid") from None
    if not isinstance(claims, dict):
        raise OAuthError(error, "claims must be a JSON object")
    return header, claims


def _int_claim(claims: dict, name: str, required: bool) -> Optional[int]:
    v = claims.get(name)
    if v is None:
        if required:
            raise OAuthError("invalid_client", f"{name} missing")
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise OAuthError("invalid_client", f"{name} is no number")
    return int(v)


def check_times(claims: dict, now: int, error: str = "invalid_client") -> int:
    """`exp` required, in the future and at most `MAX_ASSERTION_LIFETIME` ahead; `iat`/`nbf` not in the future.
    Returns `exp`."""
    try:
        exp = _int_claim(claims, "exp", True)
        iat = _int_claim(claims, "iat", False)
        nbf = _int_claim(claims, "nbf", False)
    except OAuthError as e:
        raise OAuthError(error, e.description) from None
    assert exp is not None
    if exp <= now - CLOCK_SKEW:
        raise OAuthError(error, "assertion expired")
    if exp > now + MAX_ASSERTION_LIFETIME + CLOCK_SKEW:
        raise OAuthError(error, f"exp lies more than {MAX_ASSERTION_LIFETIME} s ahead")
    if (iat is not None and iat > now + CLOCK_SKEW) or (nbf is not None and nbf > now + CLOCK_SKEW):
        raise OAuthError(error, "assertion not valid yet")
    return exp


def audience_ok(aud, issuer: str) -> bool:
    """RFC 10070: the issuer identifier as the SOLE audience value, compared as a plain string. The token endpoint
    URL, a list with more than one entry or anything else is refused."""
    if isinstance(aud, list):
        return len(aud) == 1 and aud[0] == issuer
    return isinstance(aud, str) and aud == issuer


# ---------- the services ----------

class ServiceClients:
    """Pairing, client authentication, tokens and keys of services. One instance per `OAuthServer` (`srv.services`)."""

    ALGORITHMS = ALGORITHMS

    def __init__(self, srv):
        self.srv = srv
        self.auth = srv.auth
        self.store = srv.store

    @property
    def cfg(self):
        return self.auth.cfg

    def _audit(self, event: str, username=None, ip=None, detail=None) -> None:
        self.auth.audit(event, username, ip, detail)

    def key_lifetime(self) -> Optional[int]:
        days = int(self.cfg.oauth_service_key_days or 0)
        return days * 86400 if days > 0 else None

    # --- pairing code (issued from an interactive session) ---
    def issue_pairing(self, user_id: int, name=None, resources=None, roles=None, actor=None, ip=None) -> dict:
        """A one-time pairing code for a service acting as `user_id`. The caller has checked who may (a fresh
        session for the own account, an admin for any). Returns `{"code", "expires_at", "resources", "roles",
        "dropped_roles", "pair_url", "issuer"}` — the code only this once."""
        from .errors import ConfigError
        u = self.store.get_user(user_id)
        if u is None or u["disabled"]:
            raise ConfigError("The account does not exist or is locked.")
        configured = self.srv.resources()
        if resources is None or resources == []:
            if len(configured) != 1:
                raise ConfigError("Name the resources the service may use — oauth_resources has "
                                  f"{len(configured)} entries.")
            wanted = list(configured)
        else:
            if not isinstance(resources, list) or not all(isinstance(r, str) for r in resources):
                raise ConfigError("resources must be a list of URLs")
            wanted = []
            for r in resources:
                n = normalize_resource(r)
                if n is None or n not in configured:
                    raise ConfigError(f"Unknown resource {r!r} — allowed: {configured}")
                if n not in wanted:
                    wanted.append(n)
        dropped: list = []
        scope = None
        if roles is not None:
            if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
                raise ConfigError("roles must be a list of role names")
            have = set(self.auth.user_roles(u))
            dropped = sorted(set(roles) - have)
            scope = sorted(set(roles) & have)
            # As with an API key: an empty scope would mean "all the account's roles" — refuse instead.
            if not scope:
                raise ConfigError(f"Role scope {sorted(set(roles))} contains no role of the account "
                                  f"({sorted(have) or 'none'}). Leave roles out to inherit the account's roles.")
        label = _clean_name(name) or "service"
        code = new_pairing_code()
        ttl = int(self.cfg.oauth_pairing_minutes) * 60
        expires = _now() + ttl
        self.store.add_magic_token(code_digest(normalize_code(code) or ""), "oauth_pairing", expires, int(u["id"]),
                                   None, {"name": label, "resources": wanted, "roles": scope,
                                          "created_by": actor or u["username"]})
        detail = (f"user={u['id']} name={_detail(label)} resources={_detail(','.join(wanted))}"
                  + (f" roles={_detail(','.join(scope))}" if scope is not None else "")
                  + (f" dropped_roles={_detail(','.join(dropped))}" if dropped else ""))
        self._audit("oauth_pairing_issued", u["username"], ip, detail)
        return {"code": code, "expires_at": expires, "resources": wanted, "roles": scope, "dropped_roles": dropped,
                "pair_url": self.srv.endpoint("/auth/oauth/pair"), "issuer": self.srv.issuer()}

    def pair(self, body, ip) -> dict:
        """`_pair` with every refusal in the audit log (`oauth_pair_denied reason=…`)."""
        try:
            return self._pair(body, ip)
        except OAuthError as e:
            if e.status != 429:
                self._audit("oauth_pair_denied", None, ip,
                            f"reason={getattr(e, 'reason', e.error)} error={e.error}")
            raise

    def _pair(self, body, ip) -> dict:
        """Redeem a pairing code (`POST /auth/oauth/pair`): `{"code", "jwk", "proof"}`. The proof is a JWS signed with
        the private half of `jwk` — `typ` `tinysesam-pairing+jwt`, `aud` the issuer, `nonce` bound to the code,
        short `exp`. Only then is the code consumed and the service created, in one transaction."""
        from .security import ip_bucket
        if not self.auth.rl.allow(("oauth_pair", ip_bucket(ip)), PAIR_PER_IP_HOUR, 3600):   # IPv6 per /64
            raise OAuthError("temporarily_unavailable", "too many pairing attempts from this address", 429)
        if not isinstance(body, dict):
            raise OAuthError("invalid_request", "a JSON object is expected")
        code = normalize_code(body.get("code"))
        if code is None:
            raise _pair_refused("malformed_code")
        jwk, kid = public_jwk(body.get("jwk"))
        now = _now()
        try:
            header, claims = verify(str(body.get("proof") or ""), jwk, typ=PAIRING_TYP, plain_ok=False,
                                    error="invalid_request")
            check_times(claims, now, error="invalid_request")
        except OAuthError as e:
            raise _pair_refused("proof", e.description) from None
        if not audience_ok(claims.get("aud"), self.srv.issuer()):
            raise _pair_refused("proof", "aud must be the issuer")
        if claims.get("nonce") != code_binding(code):
            raise _pair_refused("proof", "the proof belongs to another code")
        row = self.store.get_magic_token(code_digest(code))
        if (row is None or row["purpose"] != "oauth_pairing" or row["used_at"] is not None
                or row["expires_at"] < now or row["user_id"] is None):
            raise _pair_refused("code")
        u = self.store.get_user(row["user_id"])
        if u is None or u["disabled"]:
            raise _pair_refused("account")
        payload = json.loads(row["payload"] or "{}")
        configured = self.srv.resources()
        resources = [r for r in payload.get("resources") or [] if r in configured]
        if not resources:
            raise OAuthError("invalid_target", "none of the code's resources is configured any more")
        client_id = CLIENT_PREFIX + secrets.token_urlsafe(18)
        lifetime = self.key_lifetime()
        key = {"kid": kid, "jwk": jwk, "expires_at": now + lifetime if lifetime else None}
        if not self.store.oauth_pair_service(code_digest(code), now, client_id, payload.get("name") or "service",
                                             int(u["id"]), payload.get("roles"), resources,
                                             payload.get("created_by"), ip, key):
            raise _pair_refused("code")
        self._audit("oauth_service_paired", u["username"], ip,
                    f"client={client_id} name={_detail(payload.get('name'))} kid={kid} alg={header.get('alg')}")
        self.auth._security_event("oauth_service_paired", u["id"], client_id=client_id,
                                  client_name=payload.get("name") or "service", resources=list(resources))
        return {"client_id": client_id, "issuer": self.srv.issuer(), "token_endpoint": self.srv.endpoint(
            "/auth/oauth/token"), "key_endpoint": self.srv.endpoint("/auth/oauth/service/keys"),
            "resources": resources, "kid": kid, "key_expires_at": key["expires_at"],
            "token_endpoint_auth_method": "private_key_jwt", "grant_types": ["client_credentials"]}

    # --- client authentication (RFC 7523 §2.2) ---
    def authenticate(self, form: dict, ip) -> tuple[dict, dict]:
        """(service, key) of a valid client assertion — or `OAuthError("invalid_client", 401)`. The reason goes to the
        audit log (throttled), the answer stays generic."""
        try:
            return self._authenticate(form)
        except OAuthError as e:
            reason = e.description or e.error
            if self.auth._once_per(("oauth_client_auth", ip or "?", reason), 60):
                self._audit("oauth_client_auth_failed", None, ip,
                            f"client={_detail(form.get('client_id') or _claimed_client(form))} "
                            f"reason={_detail(reason)}")
            if e.error != "invalid_client":
                raise
            err = OAuthError("invalid_client", "client authentication failed", 401)
            err.reason = reason   # type: ignore[attr-defined]
            raise err from None

    def _authenticate(self, form: dict) -> tuple[dict, dict]:
        if form.get("client_secret"):
            raise OAuthError("invalid_client", "client_secret is not accepted — private_key_jwt only")
        if form.get("client_assertion_type") != ASSERTION_TYPE:
            raise OAuthError("invalid_client", "client_assertion_type must be jwt-bearer")
        assertion = form.get("client_assertion") or ""
        _, peek = _segments(assertion)
        client_id = peek.get("iss")      # only to find the client — checked again after the signature
        if not isinstance(client_id, str) or not client_id.startswith(CLIENT_PREFIX):
            raise OAuthError("invalid_client", "iss and sub must both be the client_id")
        if form.get("client_id") and form.get("client_id") != client_id:
            raise OAuthError("invalid_client", "client_id does not match the assertion")
        svc = self.store.oauth_service(client_id)
        if svc is None:
            raise OAuthError("invalid_client", "unknown client")
        if svc["revoked_at"] is not None:
            raise OAuthError("invalid_client", "client revoked")
        now = _now()
        # The key is ours, found by the client ID — never one the token brings along (jwk/jku/x5u/x5c).
        keys = [k for k in self.store.oauth_client_keys(client_id)
                if (k["retire_at"] is None or k["retire_at"] > now) and (k["expires_at"] is None or k["expires_at"] > now)]
        if not keys:
            raise OAuthError("invalid_client", "no valid key — the key expired or the client was rotated away")
        header, _ = _segments(assertion)
        kid = header.get("kid")
        if kid is not None:
            keys = [k for k in keys if k["kid"] == kid]
            if not keys:
                raise OAuthError("invalid_client", "unknown kid")
        claims, used = None, None
        last = OAuthError("invalid_client", "signature invalid")
        for k in keys:
            try:
                _, claims = verify(assertion, k["jwk"], typ=ASSERTION_TYP, plain_ok=True)
                used = k
                break
            except OAuthError as e:
                last = e
        if used is None or claims is None:
            raise last
        if claims.get("iss") != client_id or claims.get("sub") != client_id:
            raise OAuthError("invalid_client", "iss and sub must both be the client_id")
        if not audience_ok(claims.get("aud"), self.srv.issuer()):
            raise OAuthError("invalid_client", "aud must be the issuer identifier as the only value")
        exp = check_times(claims, now)
        jti = claims.get("jti")
        if not isinstance(jti, str) or not _JTI.fullmatch(jti):
            raise OAuthError("invalid_client", "jti missing or malformed")
        # Only after the signature: a stranger cannot fill the replay table.
        if not self.store.oauth_note_assertion(client_id, jti, exp + CLOCK_SKEW):
            raise OAuthError("invalid_client", "assertion replayed (jti already used)")
        return svc, used

    # --- token endpoint ---
    def token(self, form: dict, ip) -> dict:
        svc, key = self.authenticate(form, ip)
        scope = str(form.get("scope") or DEFAULT_SCOPE)
        if scope != DEFAULT_SCOPE:
            raise OAuthError("invalid_scope", f"a service gets scope {DEFAULT_SCOPE} only (no refresh token)")
        allowed = [r for r in svc["resources"] if r in self.srv.resources()]
        if form.get("resource"):
            resource = normalize_resource(form["resource"])
            if resource is None or resource not in allowed:
                raise OAuthError("invalid_target", "resource not allowed for this client")
        elif len(allowed) == 1:
            resource = allowed[0]
        else:
            raise OAuthError("invalid_target", "name the resource (the client may use several)")
        u = self.store.get_user(svc["user_id"])
        if u is None or u["disabled"]:
            raise OAuthError("invalid_grant", "the account is not active")
        ttl = int(self.cfg.oauth_service_token_ttl_sec)
        now = _now()
        at = new_token(ACCESS_PREFIX)
        grant_id = self.store.oauth_service_token(svc["client_id"], int(u["id"]), resource, DEFAULT_SCOPE, now, ip,
                                                  key["kid"], (self.srv.digest(at), "access", DEFAULT_SCOPE, now + ttl))
        self._audit("oauth_service_token", u["username"], ip,
                    f"client={svc['client_id']} grant={grant_id} kid={key['kid']} resource={_detail(resource)}")
        out = {"access_token": at, "token_type": "Bearer", "expires_in": ttl, "scope": DEFAULT_SCOPE}
        if key["expires_at"]:
            # Not a standard field: tells the reference client when to rotate.
            out["key_expires_at"] = int(key["expires_at"])
        return out

    # --- key rotation ---
    def rotate_key(self, form: dict, ip) -> dict:
        """`POST /auth/oauth/service/keys`: authenticated with an assertion of THE current key; `jwk` = the new public
        key, `proof` = a JWS of the new key (`typ` `tinysesam-key+jwt`, `aud` issuer, `sub` client ID). The new key
        becomes current at once; every other key is accepted only `KEY_OVERLAP_SEC` longer — at the token endpoint,
        not here. Sending the same new key again (an answer got lost, the client crashed before it saved the
        rotation) is answered as a success, also when the assertion comes from the key it replaced: the proof shows
        possession of the current key, so nothing changes hands.

        A key within its overlap may not rotate (attack round 2026-11-21, A-2): with a copy of the old key a stranger
        would rotate in a key of their own, and the rightful new key would run out after the overlap instead."""
        svc, used = self.authenticate(form, ip)
        jwk, kid = public_jwk(form.get("jwk"))
        now = _now()
        try:
            _, claims = verify(str(form.get("proof") or ""), jwk, typ=KEY_TYP, plain_ok=False, error="invalid_request")
            check_times(claims, now, error="invalid_request")
        except OAuthError as e:
            raise OAuthError("invalid_request", "proof of possession of the new key failed: " + e.description) from None
        if not audience_ok(claims.get("aud"), self.srv.issuer()) or claims.get("sub") != svc["client_id"]:
            raise OAuthError("invalid_request", "proof: aud must be the issuer and sub the client_id")
        keys = self.store.oauth_client_keys(svc["client_id"])
        same = [k for k in keys if k["kid"] == kid]
        if same:
            if same[0]["retire_at"] is None:
                return self._key_answer(svc, same[0], keys)
            raise OAuthError("invalid_request", "this key was already replaced — create a new one")
        if used["retire_at"] is not None:
            self._audit("oauth_service_key_rotate_refused", svc["username"], ip,
                        f"client={svc['client_id']} kid={used['kid']} reason=key_in_overlap")
            raise OAuthError("invalid_client", "only the current key may rotate — this key was already replaced", 401)
        live = [k for k in keys if k["retire_at"] is None or k["retire_at"] > now]
        if len(live) >= MAX_KEYS:
            raise OAuthError("invalid_request", f"at most {MAX_KEYS} keys at once — wait for the overlap to end")
        lifetime = self.key_lifetime()
        new = {"kid": kid, "jwk": jwk, "expires_at": now + lifetime if lifetime else None}
        if not self.store.oauth_add_client_key(svc["client_id"], new, now, ip, now + KEY_OVERLAP_SEC):
            raise OAuthError("invalid_client", "client revoked", 401)
        self._audit("oauth_service_key_rotated", svc["username"], ip,
                    f"client={svc['client_id']} kid={kid} previous_until={now + KEY_OVERLAP_SEC}")
        return self._key_answer(svc, dict(new, retire_at=None), self.store.oauth_client_keys(svc["client_id"]))

    @staticmethod
    def _key_answer(svc: dict, key: dict, keys: list) -> dict:
        until = [int(k["retire_at"]) for k in keys if k["kid"] != key["kid"] and k["retire_at"]]
        return {"client_id": svc["client_id"], "kid": key["kid"], "key_expires_at": key["expires_at"],
                "previous_valid_until": max(until) if until else None}

    # --- revocation and lists ---
    def revoke(self, client_id: str, reason: str, ip=None) -> bool:
        svc = self.store.oauth_service(client_id)
        if svc is None or not self.store.oauth_revoke_service(client_id, reason, _now()):
            return False
        self._audit("oauth_service_revoked", svc["username"], ip, f"client={client_id} reason={reason}")
        self.auth._security_event("oauth_service_revoked", svc["user_id"], client_id=client_id,
                                  client_name=svc["name"], reason=reason)
        return True

    def revoke_user(self, user_id: int, reason: str) -> int:
        return sum(1 for cid in self.store.oauth_service_ids(user_id) if self.revoke(cid, reason))

    def listing(self, user_id=None) -> list:
        now = _now()
        out = []
        for s in self.store.oauth_services(user_id=user_id):
            keys = self.store.oauth_client_keys(s["client_id"])
            out.append({
                "client_id": s["client_id"], "name": s["name"], "user_id": int(s["user_id"]),
                "username": s["username"], "roles": s["roles"], "resources": s["resources"],
                "created_at": s["created_at"], "created_by": s["created_by"] or "", "last_used": s["last_used"],
                "last_ip": s["last_ip"] or s["created_ip"] or "",
                "keys": [{"kid": k["kid"], "alg_family": k["jwk"]["crv"], "created_at": k["created_at"],
                          "expires_at": k["expires_at"], "retire_at": k["retire_at"], "last_used": k["last_used"],
                          "valid": (k["retire_at"] is None or k["retire_at"] > now)
                                   and (k["expires_at"] is None or k["expires_at"] > now)} for k in keys]})
        return out


def _claimed_client(form: dict) -> str:
    """The client ID an assertion CLAIMS (`iss`) — for the audit line of a refusal only, never trusted."""
    try:
        return str(_segments(form.get("client_assertion") or "")[1].get("iss") or "")[:60]
    except OAuthError:
        return ""


def _clean_name(name) -> str:
    if name is not None and not isinstance(name, str):
        return ""
    return "".join(z for z in (name or "") if z >= " " and z != "\x7f" and not 0x202a <= ord(z) <= 0x202e
                   and not 0x2066 <= ord(z) <= 0x2069).strip()[:MAX_NAME_LEN]


def _pair_refused(reason: str, description: str = "") -> OAuthError:
    """One answer for every refused code: unknown, used, expired, another account's — the caller learns nothing."""
    text = {"code": "unknown, used or expired pairing code", "malformed_code": "unknown, used or expired pairing code",
            "account": "unknown, used or expired pairing code"}.get(reason, "proof of possession failed")
    e = OAuthError("invalid_grant" if reason != "proof" else "invalid_request",
                   text + (f": {description}" if description and reason == "proof" else ""))
    e.reason = reason   # type: ignore[attr-defined]
    return e

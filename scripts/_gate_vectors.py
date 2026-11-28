#!/usr/bin/env python3
"""Generate the language-neutral gate client vectors in `spec/vectors/` from the real TinySesam code (T-28).

    python scripts/_gate_vectors.py           # write spec/vectors/*.json
    python scripts/_gate_vectors.py --check   # exit 1 when a file differs from what the code generates now

The valid tokens come from TinySesam's own issuing path (`TinySesam._gate_cookie`, `gate.issue`), the header-mode
inputs from `TinySesam._forward_response_headers`, the top bar from `TinySesam.topbar_data` — so the vectors follow
the server. The attacks are built here byte by byte, signed with the fixed test keys. The expected verdict of every
vector is written down here by hand, never computed by a verifier: a verifier that wrote its own expectations would
pass by construction. `tests/test_gate_vectors.py` checks the files against this generator and against the Python
gate client `tinysesam.gate_client`.

The keys are TEST MATERIAL: derived from a public label, printed in `spec/vectors/keys.json`, worthless as a secret.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import sys
import tempfile
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "spec", "vectors")

FORMAT = 2                # spec version 2: Remote-Kind / ts_kind (account_kind)
NOW = 1767225600          # 2026-01-01T00:00:00Z
ISSUER = "https://auth.example.com"
AUDIENCE = "app.example.com"
TTL = 300
TOKEN_TYPE = "tinysesam-gate+jwt"
MAX_TOKEN_BYTES = 4096


# ---------- test keys ----------

def _seed(label: str) -> bytes:
    return hashlib.sha256(b"tinysesam gate-client test vector key " + label.encode("ascii")).digest()


def _private(label: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(_seed(label))


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _public(label: str) -> bytes:
    from tinysesam import gate
    return gate.public_raw(_private(label))


def kid(label: str) -> str:
    from tinysesam import gate
    return gate.key_name_id(_public(label))


def gate_kid(raw: bytes) -> str:
    """The kid rule of spec §4.1 over arbitrary bytes (for an entry whose only defect is elsewhere)."""
    return hashlib.sha256(raw).hexdigest()[:16]


def jwk(label: str) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(_public(label)), "kid": kid(label), "alg": "EdDSA", "use": "sig"}


def jwks(*labels: str) -> dict:
    return {"keys": [jwk(lb) for lb in labels]}


# ---------- raw building blocks for the attacks ----------

def enc(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def head(label: str = "A", **change) -> dict:
    h = {"alg": "EdDSA", "typ": TOKEN_TYPE, "kid": kid(label)}
    for k, v in change.items():
        if v is None:
            h.pop(k, None)
        else:
            h[k] = v
    return h


def signed(h, payload, signer: str = "A") -> str:
    """JWS Compact over arbitrary header/payload (dict or raw bytes), Ed25519 with a test key."""
    hs = b64u(h if isinstance(h, bytes) else enc(h))
    ps = b64u(payload if isinstance(payload, bytes) else enc(payload))
    return f"{hs}.{ps}." + b64u(_private(signer).sign(f"{hs}.{ps}".encode("ascii")))


def hmac_signed(h, payload, secret: bytes) -> str:
    hs, ps = b64u(enc(h)), b64u(enc(payload))
    return f"{hs}.{ps}." + b64u(hmac.new(secret, f"{hs}.{ps}".encode("ascii"), hashlib.sha256).digest())


def claims_of(jws: str) -> dict:
    p = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


@contextlib.contextmanager
def _fixed(jti_prefix: str):
    """TinySesam's issuing path with a fixed clock and fixed `jti` values — the only two inputs that vary per run."""
    from tinysesam import gate, manager
    count = iter(range(10 ** 6))
    old_secrets, old_now = gate.secrets, manager._wall_now
    gate.secrets = types.SimpleNamespace(token_urlsafe=lambda n=None: f"{jti_prefix}-{next(count)}")
    manager._wall_now = lambda: NOW
    try:
        yield
    finally:
        gate.secrets, manager._wall_now = old_secrets, old_now


def issue(label: str, *, sub: str, claims: dict, now: int = NOW, ttl: int = TTL, aud: str = AUDIENCE,
          iss: str = ISSUER, jti: str = "jti") -> str:
    """A token from `gate.issue` itself (standard header, `ts_` prefix, iat/nbf/exp/jti) with a test key."""
    from tinysesam import gate
    with _fixed(jti):
        return gate.issue(_private(label), iss=iss, aud=aud, sub=sub, claims=claims, ttl=ttl, now=now)


# ---------- the probe installation ----------

class Probe:
    """A throwaway TinySesam with key A as its gate key and a handful of accounts."""

    def __init__(self):
        from tinysesam import TinySesam, TinySesamConfig
        self.dir = tempfile.mkdtemp(prefix="tinysesam-vectors-")
        key_file = os.path.join(self.dir, "gate.key")
        with open(key_file, "w", encoding="ascii") as f:
            f.write(base64.b64encode(_seed("A")).decode("ascii") + "\n")
        os.chmod(key_file, 0o600)
        with open(os.devnull, "w") as quiet, contextlib.redirect_stderr(quiet):
            self.auth = TinySesam(TinySesamConfig(
                db_path=os.path.join(self.dir, "probe.db"), base_url=ISSUER, forward_auth_enabled=True,
                gate_token_enabled=True, gate_key_file=key_file, trusted_redirect_hosts=[AUDIENCE],
                passkey_enabled=False, oidc_enabled=False, rp_name="Example",
                topbar_links=[("Wiki", "https://app.example.com/wiki"), ("Files", "/files/")],
                topbar_menu_links=[("My collections", "/collections"),
                                   ("App admin", "https://app.example.com/admin", {"admin": True})]))
        a = self.auth
        self.users = {
            "anna": a.create_user("anna", None, roles=["editors"], display_name="Anna Berg",
                                  email="anna@example.com"),
            "admin": a.create_user("admin", None, is_admin=True, display_name="Admin", email="admin@example.com"),
            "juergen": a.create_user("juergen", None, roles=["editors", "reviewers"], display_name="Jürgen Müller",
                                     email="juergen@example.com"),
            "ivan": a.create_user("иван", None, roles=["readers"], display_name="Иван Петров"),
            "homoglyph": a.create_user("аdmin", None, roles=["аdmin"], display_name="Not The Admin"),
            "service": a.create_service("backup-bot", roles=["editors"], display_name="Backup Bot"),
        }
        assert a.gate_public_key() == base64.b64encode(_public("A")).decode("ascii"), "probe does not use key A"

    def close(self) -> None:
        import shutil
        self.auth.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def user(self, name: str, via: str = "session") -> dict:
        u = dict(self.auth.get_user(self.users[name]))
        u["_via"] = via
        return u

    def token(self, name: str, roles_groups=(), fields=None, jti: str = "jti") -> str:
        """The gate token exactly as `/auth/forward` would issue it for a session of this account."""
        u = self.user(name)
        saved = self.auth.cfg.forward_headers
        if fields is not None:
            self.auth.cfg.forward_headers = fields
        try:
            with _fixed(jti):
                cookie = self.auth._gate_cookie(None, u, f"https://{AUDIENCE}/x", roles_groups,
                                                session={"mfa_ok": 1, "user_id": u["id"]})
        finally:
            self.auth.cfg.forward_headers = saved
        assert cookie, "no gate token issued"
        return cookie.split(";", 1)[0].split("=", 1)[1]

    def headers(self, name: str, via: str = "session", host: str = "") -> dict:
        return dict(self.auth._forward_response_headers(self.user(name, via), host))

    def topbar(self, name=None) -> dict:
        viewer = self.auth.get_user(self.users[name]) if name else None
        return self.auth.topbar_data(viewer, base=ISSUER)


# ---------- expected identity (written out by the rules, not by the reference) ----------

def groups(text: str) -> list:
    out = []
    for part in text.split(","):
        g = part.strip(" ")
        if g and g not in out:
            out.append(g)
    return out


def identity(claims: dict) -> dict:
    auth = claims.get("ts_auth", "")
    return {"user": claims.get("ts_user", ""), "name": claims.get("ts_name", ""), "email": claims.get("ts_email", ""),
            "groups": groups(claims.get("ts_groups", "")), "id": claims["sub"],
            "auth": auth if auth in ("session", "oauth", "apikey", "app-password") else "",
            "kind": "session" if auth == "session" else "token", "account_kind": claims["ts_kind"]}


# ---------- token vectors ----------

def token_vectors(p: Probe) -> list:
    out = []

    def add(vid, reason, jws, *, error=None, attack=None, now=NOW, leeway=0, audience=AUDIENCE, issuer=ISSUER,
            keys=("A",), guards=None):
        exp: dict
        if error:
            exp = {"ok": False, "error": error}
        else:
            c = claims_of(jws)
            exp = {"ok": True, "claims": c, "identity": identity(c)}
            if guards:
                exp["has_role"] = guards
        out.append({"id": vid, "attack": attack, "reason": reason,
                    "input": {"jws": jws, "now": now, "leeway": leeway, "issuer": issuer, "audience": audience,
                              "jwks": jwks(*keys)},
                    "expected": exp})

    anna = p.token("anna")
    base = claims_of(anna)

    def variant(**change):
        c = dict(base)
        for k, v in change.items():
            if v is None:
                c.pop(k, None)
            else:
                c[k] = v
        return c

    # --- valid ---
    add("valid-session", "A token as /auth/forward issues it for a session: every claim, Remote-Auth `session`.",
        anna, guards={"editors": True, "admin": False, "Editors": False})
    add("valid-admin", "The admin flag arrives as the group `admin`, nothing else implies it.", p.token("admin"),
        guards={"admin": True, "editors": False})
    add("valid-unicode", "Names beyond Latin-1 travel unchanged in the claims (UTF-8 JSON).", p.token("ivan"),
        guards={"readers": True})
    add("valid-two-groups", "Several roles are one comma-separated string in ts_groups.", p.token("juergen"),
        guards={"editors": True, "reviewers": True, "admin": False})
    roles_aud = p.token("anna", roles_groups=[["editors", "admin"]])
    add("valid-roles-audience", "A token issued for a check with roles carries them in `aud`; the client is configured "
        "with exactly that string.", roles_aud, audience="app.example.com|roles=admin,editors")
    add("valid-without-remote-auth", "An installation whose forward_headers leave out `auth` issues no ts_auth: the "
        "request counts as a token, never as a session.",
        p.token("anna", fields={"user": "Remote-User", "groups": "Remote-Groups"}))
    add("valid-rotation-active", "Two keys in the set after a rotation: the active key verifies.", anna, keys=("A", "B"))
    prev = issue("B", sub=base["sub"], claims={k[3:]: v for k, v in base.items() if k.startswith("ts_")}, jti="prev")
    add("valid-rotation-previous", "A token signed before the rotation stays valid while its key is in the set.",
        prev, keys=("A", "B"))
    add("valid-nbf-equals-now", "nbf == now is valid (nbf <= now + leeway).", anna, now=NOW)
    add("valid-last-second", "now == exp - 1 is the last valid second without leeway.", anna, now=NOW + TTL - 1)
    add("valid-leeway-nbf-edge", "With 30 s leeway a token whose nbf lies 30 s ahead is valid.", anna, now=NOW - 30,
        leeway=30)
    add("valid-leeway-exp-edge", "With 30 s leeway the token is valid until exp + 29.", anna, now=NOW + TTL + 29,
        leeway=30)
    add("valid-typ-case", "`typ` is a media type: compared ASCII case-insensitively.",
        signed(head(typ="TinySesam-Gate+JWT"), base))
    add("valid-aud-array", "`aud` may be an array (RFC 7519); one entry must equal the configured audience.",
        signed(head(), variant(aud=["other.example.com", AUDIENCE])))
    add("valid-unknown-claim", "Claims the client does not know are ignored.", signed(head(), variant(foo={"bar": 1})))
    add("valid-homoglyph-user", "A Cyrillic `а` makes another name: the identity is the exact string, the guard for "
        "`admin` stays closed.", p.token("homoglyph"), attack="unicode-homoglyph",
        guards={"admin": False, "аdmin": True})
    add("valid-zero-width-group", "A zero-width joiner is no control character; the group is not `admin`.",
        issue("A", sub="7", claims={"user": "zw", "groups": "ad‍min", "id": "7", "auth": "session", "kind": "user"},
              jti="zw"),
        attack="unicode-homoglyph", guards={"admin": False})
    add("valid-bidi-name", "A right-to-left override in the name is allowed; rendering it safely is the app's job.",
        issue("A", sub="8", claims={"user": "bidi", "name": "evil‮txt.exe", "groups": "", "id": "8",
                                    "auth": "session", "kind": "user"}, jti="bidi"), attack="unicode-homoglyph")

    # The largest valid token: a long display name, padded until the next character would cross the limit.
    size_ok = size_over = None
    for n in range(2600, 3200):
        t = signed(head(), variant(ts_name="x" * n))
        if len(t) <= MAX_TOKEN_BYTES:
            size_ok = t
        elif size_over is None:
            size_over = t
    add("valid-size-limit", f"The largest token of this form within the limit of {MAX_TOKEN_BYTES} bytes "
        f"({len(size_ok)} bytes).", size_ok)

    # --- algorithm ---
    hs, ps, _sig = anna.split(".")
    none_head = b64u(enc(head(alg="none")))
    add("attack-alg-none", "`alg: none` without a signature. The algorithm is fixed to EdDSA.",
        f"{none_head}.{ps}.", error="header", attack="alg-none")
    add("attack-alg-none-signed", "`alg: none` with a valid Ed25519 signature: still not EdDSA.",
        signed(head(alg="none"), base), error="header", attack="alg-none")
    add("attack-alg-none-case", "`alg: NoNe` — no case-insensitive comparison of alg.",
        f"{b64u(enc(head(alg='NoNe')))}.{ps}.", error="header", attack="alg-none")
    add("attack-hs256-raw-public-key", "HS256 with the 32 raw public key bytes as HMAC secret (algorithm confusion).",
        hmac_signed(head(alg="HS256"), base, _public("A")), error="header", attack="alg-confusion-hs256")
    add("attack-hs256-base64-public-key", "HS256 with the Base64 text of the public key (the proxy's sign_key) as "
        "secret.", hmac_signed(head(alg="HS256"), base, base64.b64encode(_public("A"))), error="header",
        attack="alg-confusion-hs256")
    add("attack-alg-es256", "A valid Ed25519 signature under the header `alg: ES256`.", signed(head(alg="ES256"), base),
        error="header", attack="alg-wrong")
    add("attack-alg-ed25519", "`alg: Ed25519` (RFC 9864 name) is not the EdDSA this protocol fixes.",
        signed(head(alg="Ed25519"), base), error="header", attack="alg-wrong")
    add("attack-alg-lowercase", "`alg: eddsa` — alg is compared exactly.", signed(head(alg="eddsa"), base),
        error="header", attack="alg-wrong")
    add("attack-alg-missing", "The alg header member is missing.", signed(head(alg=None), base), error="header", attack="alg-wrong")
    add("attack-alg-array", "alg as an array containing EdDSA.", signed(head(alg=["EdDSA"]), base), error="header",
        attack="alg-wrong")
    add("attack-typ-jwt", "A plain JWT signed with the gate key (`typ: JWT`) is no gate token.",
        signed(head(typ="JWT"), base), error="header", attack="typ-wrong")
    add("attack-typ-missing", "The typ header member is missing.", signed(head(typ=None), base), error="header", attack="typ-wrong")
    add("attack-typ-application-prefix", "`application/tinysesam-gate+jwt` is refused: exactly one spelling.",
        signed(head(typ="application/" + TOKEN_TYPE), base), error="header", attack="typ-wrong")

    # --- header members ---
    add("attack-crit", "`crit` names an extension the client does not implement — refused (RFC 7515 §4.1.11).",
        signed(dict(head(), crit=["exp"]), base), error="header", attack="crit")
    add("attack-crit-b64", "`crit: [b64]` with `b64: false` (RFC 7797, unencoded payload).",
        signed(dict(head(), crit=["b64"], b64=False), base), error="header", attack="crit")
    add("attack-embedded-jwk", "A `jwk` in the header carrying the attacker's key, signed with it. Keys come only from "
        "the configuration.", signed(dict(head("X"), jwk=jwk("X")), base, "X"), error="header", attack="embedded-key")
    add("attack-embedded-jwk-known-kid", "An embedded `jwk` of the attacker under the kid of a trusted key.",
        signed(dict(head("A"), jwk=jwk("X")), base, "X"), error="header", attack="embedded-key")
    add("attack-jku", "`jku` points to a key set of the attacker, in an otherwise valid token: only refusing the member "
        "stops it.", signed(dict(head(), jku="https://evil.example.com/jwks.json"), base), error="header",
        attack="embedded-key")
    add("attack-x5u", "`x5u` points to a certificate of the attacker, in an otherwise valid token.",
        signed(dict(head(), x5u="https://evil.example.com/cert.pem"), base), error="header",
        attack="embedded-key")
    add("attack-x5c", "`x5c` embeds a certificate chain.", signed(dict(head(), x5c=["MIIB"]), base), error="header",
        attack="embedded-key")
    add("attack-cty-nested", "`cty: JWT` announces a nested token; the header carries exactly alg, typ and kid.",
        signed(dict(head(), cty="JWT"), base), error="header", attack="header-unknown-member")
    add("attack-zip", "`zip` is a JWE member and has no place here.", signed(dict(head(), zip="DEF"), base),
        error="header", attack="header-unknown-member")

    # --- keys ---
    add("attack-foreign-key", "Signed with a key outside the set, under its own kid.", signed(head("X"), base, "X"),
        error="kid", attack="foreign-key")
    add("attack-foreign-key-trusted-kid", "Signed with a foreign key under the kid of the trusted key.",
        signed(head("A"), base, "X"), error="signature", attack="foreign-key")
    add("attack-previous-key-not-in-set", "A token of key B against a set that holds only A.", prev, error="kid",
        attack="kid-unknown")
    add("attack-kid-missing", "The kid header member is missing.", signed(head(kid=None), base), error="kid", attack="kid-manipulated")
    add("attack-kid-path", "kid as a path: it is never used as a file name.", signed(head(kid="../../../etc/passwd"),
        base), error="kid", attack="kid-manipulated")
    add("attack-kid-sql", "kid as SQL: it is never used in a query.", signed(head(kid="' OR '1'='1"), base),
        error="kid", attack="kid-manipulated")
    add("attack-kid-long", "A kid of 1500 characters.", signed(head(kid="a" * 1500), base), error="kid",
        attack="kid-manipulated")
    add("attack-kid-number", "The kid is a JSON number, not a string.", signed(head(kid=12345), base), error="kid", attack="kid-manipulated")
    add("attack-kid-uppercase", "The trusted kid in upper case: kids are compared exactly.",
        signed(head(kid=kid("A").upper()), base), error="kid", attack="kid-manipulated")
    add("attack-kid-nul", "A NUL character after the trusted kid.", signed(head(kid=kid("A") + "\x00"), base),
        error="kid", attack="kid-manipulated")

    # --- signature ---
    add("attack-empty-signature", "A valid header and payload with an empty signature.", f"{hs}.{ps}.",
        error="signature", attack="empty-signature")
    sig = base64.urlsafe_b64decode(_sig + "==")
    add("attack-short-signature", "A signature one byte short (63 bytes).", f"{hs}.{ps}.{b64u(sig[:-1])}", error="signature",
        attack="bad-signature")
    tampered = b64u(enc(variant(ts_groups="editors,admin")))
    add("attack-payload-swapped", "The payload changed after signing (admin added).", f"{hs}.{tampered}.{_sig}",
        error="signature", attack="bad-signature")
    add("attack-signature-bitflip", "One bit of the signature flipped.",
        f"{hs}.{ps}.{b64u(bytes([sig[0] ^ 1]) + sig[1:])}", error="signature", attack="bad-signature")

    # --- encoding ---
    add("attack-padding-signature", "The signature with `=` padding: base64url without padding only.",
        f"{anna}==", error="malformed", attack="base64-padding")
    padded_h = b64u(enc(head())) + "=" * (-len(b64u(enc(head()))) % 4)
    if padded_h.endswith("="):
        ph = f"{padded_h}.{ps}"
        add("attack-padding-header-resigned", "A padded header segment, signed over exactly these bytes.",
            ph + "." + b64u(_private("A").sign(ph.encode("ascii"))), error="malformed", attack="base64-padding")
    std = None
    for i in range(200):
        t = signed(head(), variant(jti=f"alphabet-{i}"))
        s = t.split(".")[2]
        if "-" in s or "_" in s:
            std = t.rsplit(".", 1)[0] + "." + s.replace("-", "+").replace("_", "/")
            break
    add("attack-standard-alphabet", "The signature in the standard Base64 alphabet (`+`, `/`).", std,
        error="malformed", attack="base64-alphabet")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = _sig[-1]
    noncanon = _sig[:-1] + alphabet[alphabet.index(last) + 1]
    add("attack-noncanonical-base64", "The last signature character with non-zero unused bits: decodes to the same "
        "bytes in a lenient decoder, refused in a strict one.", f"{hs}.{ps}.{noncanon}", error="malformed",
        attack="base64-noncanonical")
    add("attack-newline-in-signature", "A line break inside the signature segment.",
        f"{hs}.{ps}.{_sig[:40]}\n{_sig[40:]}", error="malformed", attack="base64-alphabet")
    add("attack-two-segments", "Two segments instead of three.", f"{hs}.{ps}", error="malformed", attack="segments")
    add("attack-four-segments", "An extra segment after the signature.", f"{anna}.{ps}", error="malformed",
        attack="segments")
    add("attack-trailing-dot", "A trailing dot (an empty fourth segment).", f"{anna}.", error="malformed",
        attack="segments")
    add("attack-five-segments-jwe", "Five segments, shaped like a JWE.", f"{hs}.{ps}.{ps}.{ps}.{_sig}",
        error="malformed", attack="segments")
    add("attack-empty-header", "An empty header segment before the payload.", f".{ps}.{_sig}", error="malformed", attack="segments")
    add("attack-oversize", f"One step above the limit of {MAX_TOKEN_BYTES} bytes ({len(size_over)} bytes), validly "
        "signed.", size_over, error="malformed", attack="oversize")
    add("attack-jws-json-flattened", "The flattened JWS JSON serialization instead of Compact.",
        json.dumps({"protected": hs, "payload": ps, "signature": _sig}), error="malformed",
        attack="jws-json-serialization")
    add("attack-jws-json-general", "The general JWS JSON serialization.",
        json.dumps({"payload": ps, "signatures": [{"protected": hs, "signature": _sig}]}), error="malformed",
        attack="jws-json-serialization")

    # --- JSON ---
    body = enc(base)[:-1]
    add("attack-duplicate-claim", "`ts_groups` twice — a parser that keeps the last one would see `admin`.",
        signed(head(), body + b',"ts_groups":"admin"}'), error="malformed", attack="duplicate-members")
    add("attack-duplicate-sub", "`sub` twice with two account IDs.", signed(head(), body + b',"sub":"1"}'),
        error="malformed", attack="duplicate-members")
    hb = enc(head())[:-1]
    add("attack-duplicate-header-alg", "`alg` twice in the header: `none` first, `EdDSA` last.",
        signed(b'{"alg":"none",' + hb[1:] + b"}", base), error="malformed", attack="duplicate-members")
    add("attack-header-array", "The header is a JSON array.", signed(b'["EdDSA"]', base), error="malformed",
        attack="json-encoding")
    add("attack-payload-array", "The payload is a JSON array.", signed(head(), b"[1,2]"), error="malformed",
        attack="json-encoding")
    add("attack-payload-invalid-utf8", "Payload bytes that are no UTF-8 (in an unknown claim, so that the token has no "
        "other defect).", signed(head(), body + b',"note":"\xff"}'), error="malformed", attack="json-encoding")
    add("attack-payload-bom", "A byte order mark before the payload JSON.", signed(head(), b"\xef\xbb\xbf" + enc(base)),
        error="malformed", attack="json-encoding")
    add("attack-payload-nan", "A NaN value in the payload is no JSON.", signed(head(), body + b',"x":NaN}'), error="malformed",
        attack="json-encoding")

    # --- claim types ---
    for vid, change, why in (
            ("exp-string", {"exp": str(base["exp"])}, "exp as a string"),
            ("exp-float", {"exp": base["exp"] + 0.5}, "exp with a fraction"),
            ("exp-bool", {"exp": True}, "exp as a boolean"),
            ("exp-huge", {"exp": 2 ** 53 + 1}, "exp beyond 2^53 - 1 (not exact in every JSON parser)"),
            ("nbf-missing", {"nbf": None}, "no nbf"),
            ("iat-missing", {"iat": None}, "no iat"),
            ("sub-missing", {"sub": None}, "no sub"),
            ("sub-number", {"sub": 1}, "sub as a number"),
            ("sub-empty", {"sub": "", "ts_id": None}, "sub empty (and no ts_id, which would differ)"),
            ("iss-missing", {"iss": None}, "no iss"),
            ("aud-number", {"aud": 1}, "aud as a number"),
            ("aud-empty-array", {"aud": []}, "aud as an empty array"),
            ("aud-array-number", {"aud": [AUDIENCE, 1]}, "aud array with a number"),
            ("groups-list", {"ts_groups": ["editors", "admin"]}, "ts_groups as a list instead of a string"),
            ("user-number", {"ts_user": 1}, "ts_user as a number"),
            ("auth-object", {"ts_auth": {"kind": "session"}}, "ts_auth as an object"),
            ("jti-number", {"jti": 5}, "jti as a number"),
            ("ts-id-differs", {"ts_id": "2"}, "ts_id differs from sub — one account, one ID"),
            ("kind-missing", {"ts_kind": None}, "no ts_kind (a token issued before spec v2, or by an older TinySesam)"),
            ("kind-type", {"ts_kind": 1}, "ts_kind as a number"),
            ("kind-case", {"ts_kind": "User"}, "ts_kind `User` — compared exactly, no case folding"),
            ("kind-unknown", {"ts_kind": "admin"}, "ts_kind `admin` — only `user` and `service` exist"),
            ("kind-service-session", {"ts_kind": "service"}, "ts_kind `service` with ts_auth `session` — a service "
             "account has no session, so TinySesam never issues such a token; only a holder of the key can mint it"),
    ):
        add(f"attack-claim-{vid}", f"Validly signed, but {why}.", signed(head(), variant(**change)), error="claims",
            attack="claim-types")

    # --- Unicode / control characters (signed: only a key holder can mint these; defence in depth) ---
    for vid, claims, why in (
            ("crlf-user", {"user": "anna\r\nRemote-Groups: admin"}, "CR/LF in ts_user (header injection)"),
            ("lf-groups", {"groups": "editors\nadmin"}, "a line break in ts_groups"),
            ("nul-name", {"name": "Anna\x00Berg"}, "NUL in ts_name"),
            ("del-user", {"user": "anna\x7f"}, "DEL in ts_user"),
            ("tab-email", {"email": "anna@example.com\t"}, "a tab in ts_email"),
    ):
        c = {"user": "anna", "name": "Anna Berg", "email": "anna@example.com", "groups": "editors", "id": "1",
             "auth": "session", "kind": "user"}
        c.update(claims)
        add(f"attack-control-{vid}", f"{why.capitalize()}. TinySesam strips control characters before signing; a client "
            "that meets one refuses instead of stripping (stripping can produce another account's name).",
            issue("A", sub="1", claims=c, jti=vid), error="claims", attack="unicode-control")

    # --- time ---
    add("attack-expired-at-exp", "now == exp: expired (exp + leeway must be later than now).", anna, now=NOW + TTL,
        error="expired", attack="expired")
    add("attack-expired-long-ago", "A full day after expiry.", anna, now=NOW + 86400, error="expired", attack="expired")
    add("attack-expired-leeway-edge", "With 30 s leeway, now == exp + 30 is expired.", anna, now=NOW + TTL + 30,
        leeway=30, error="expired", attack="expired")
    add("attack-not-yet-valid", "One second before nbf, no leeway.", anna, now=NOW - 1, error="not_yet_valid",
        attack="not-yet-valid")
    add("attack-not-yet-valid-leeway-edge", "With 30 s leeway, nbf 31 s ahead.", anna, now=NOW - 31, leeway=30,
        error="not_yet_valid", attack="not-yet-valid")
    add("attack-iat-after-nbf", "iat later than nbf: TinySesam issues iat == nbf, a token that says otherwise was not "
        "issued by it.", signed(head(), variant(iat=NOW + 60)), error="claims", attack="claim-types")
    add("attack-lifetime-too-long", "Valid now, but exp - nbf = 7200 s exceeds the maximum of 3600 s.",
        signed(head(), variant(exp=NOW + 7200)), error="lifetime", attack="lifetime")
    add("attack-lifetime-negative", "exp lies before nbf.", signed(head(), variant(exp=NOW - 1)), error="lifetime",
        attack="lifetime")

    # --- issuer and audience ---
    add("attack-issuer-foreign", "A token from another issuer.", signed(head(), variant(iss="https://evil.example.com")),
        error="issuer", attack="issuer")
    add("attack-issuer-trailing-slash", "The issuer with a trailing slash: compared exactly.",
        signed(head(), variant(iss=ISSUER + "/")), error="issuer", attack="issuer")
    add("attack-issuer-prefix", "The configured issuer as a prefix of a longer one.",
        signed(head(), variant(iss=ISSUER + ".evil.example.com")), error="issuer", attack="issuer")
    add("attack-audience-other-host", "A token for another application.",
        signed(head(), variant(aud="other.example.com")), error="audience", attack="audience")
    add("attack-audience-case", "The audience in upper case: compared exactly.",
        signed(head(), variant(aud="APP.example.com")), error="audience", attack="audience")
    add("attack-audience-without-roles", "A token from a check without roles at a client that requires roles.", anna,
        audience="app.example.com|roles=admin", error="audience", attack="audience")
    add("attack-audience-other-roles", "A token for `editors` at a client that requires `admin`.",
        p.token("anna", roles_groups=[["editors"]]), audience="app.example.com|roles=admin", error="audience",
        attack="audience")
    add("attack-audience-array-miss", "An aud array without the configured audience.",
        signed(head(), variant(aud=["other.example.com", "app.example.com.evil.example.com"])), error="audience",
        attack="audience")
    return out


# ---------- header mode ----------

def header_vectors(p: Probe) -> list:
    out = []

    def add(vid, reason, headers, *, error=None, attack=None, ident=None, guards=None, with_kind=True):
        # Since spec v2 every request TinySesam answers carries Remote-Kind: a vector about another defect carries
        # `user`, so that it fails for its own defect and not for a missing Remote-Kind (one defect per vector).
        if with_kind and not any(k.lower() == "remote-kind" for k in headers):
            headers = dict(headers, **{"Remote-Kind": "user"})
        exp = {"ok": False, "error": error} if error else {"ok": True, "identity": ident}
        if guards:
            exp["has_role"] = guards
        out.append({"id": vid, "attack": attack, "reason": reason, "input": {"headers": headers}, "expected": exp})

    def ident(user, name="", email="", groups_=(), rid="", auth="", kind="token", account_kind="user"):
        return {"user": user, "name": name, "email": email, "groups": list(groups_), "id": rid, "auth": auth,
                "kind": kind, "account_kind": account_kind}

    uid = {k: str(v) for k, v in p.users.items()}
    add("valid-session", "The headers /auth/forward sends for a browser session.", p.headers("anna"),
        ident=ident("anna", "Anna Berg", "anna@example.com", ["editors"], uid["anna"], "session", "session"),
        guards={"editors": True, "admin": False})
    add("valid-admin", "The admin flag is the group `admin`.", p.headers("admin"),
        ident=ident("admin", "Admin", "admin@example.com", ["admin"], uid["admin"], "session", "session"),
        guards={"admin": True})
    add("valid-utf8", "Header values are UTF-8 bytes on the wire (HTTP carries octets; shown here one code point per "
        "octet). The client decodes them as UTF-8.", p.headers("juergen"),
        ident=ident("juergen", "Jürgen Müller", "juergen@example.com", ["editors", "reviewers"], uid["juergen"],
                    "session", "session"))
    add("valid-cyrillic", "A Cyrillic account name, UTF-8 on the wire.", p.headers("ivan"),
        ident=ident("иван", "Иван Петров", "", ["readers"], uid["ivan"], "session", "session"))
    add("valid-homoglyph", "A homoglyph of `admin` is another account and another group.", p.headers("homoglyph"),
        ident=ident("аdmin", "Not The Admin", "", ["аdmin"], uid["homoglyph"], "session", "session"),
        attack="unicode-homoglyph", guards={"admin": False})
    for via, value in (("oauth", "oauth"), ("apikey", "apikey"), ("app_password", "app-password")):
        add(f"valid-auth-{value}", f"Remote-Auth `{value}`: a token, not a session. Its groups may be incomplete on "
            "purpose (a token never carries admin).", p.headers("anna", via),
            ident=ident("anna", "Anna Berg", "anna@example.com", ["editors"], uid["anna"], value, "token"),
            attack="remote-auth")
    plain = {"Remote-User": "anna", "Remote-Groups": "editors"}
    add("auth-missing", "No Remote-Auth (an older TinySesam or a renamed set): counts as a token, never as a session.",
        plain, ident=ident("anna", groups_=["editors"]), attack="remote-auth")
    add("auth-empty", "An empty Remote-Auth (TinySesam could not name the way in): counts as a token.",
        dict(plain, **{"Remote-Auth": ""}), ident=ident("anna", groups_=["editors"]), attack="remote-auth")
    add("auth-unknown", "An unknown Remote-Auth value: kind token, auth reported empty.",
        dict(plain, **{"Remote-Auth": "superuser"}), ident=ident("anna", groups_=["editors"]), attack="remote-auth")
    add("auth-case", "`Session` is not `session`.", dict(plain, **{"Remote-Auth": "Session"}),
        ident=ident("anna", groups_=["editors"]), attack="remote-auth")
    for vid, text, want, why in (
            ("two", "editors,admin", ["editors", "admin"], "two groups"),
            ("spaces", "editors, admin", ["editors", "admin"], "space after the comma is trimmed"),
            ("empty-entries", ",,editors,,", ["editors"], "empty entries are dropped"),
            ("repeat", "editors,editors", ["editors"], "a repeated group counts once"),
            ("empty", "", [], "an empty header means no groups"),
            ("case", "Admin", ["Admin"], "groups are compared case-sensitively"),
            ("inner-space", "team a", ["team a"], "a space inside a group stays"),
            ("no-escape", "a\\,b", ["a\\", "b"], "there is no escape mechanism: a backslash is an ordinary character"),
    ):
        guards = {"admin": "admin" in want}
        add(f"groups-{vid}", f"Remote-Groups: {why}.", dict(plain, **{"Remote-Groups": text}),
            ident=ident("anna", groups_=want), attack="groups-parsing", guards=guards)
    add("groups-missing", "No Remote-Groups at all: no groups.", {"Remote-User": "anna"}, ident=ident("anna"),
        attack="groups-parsing", guards={"admin": False})
    add("user-missing", "No Remote-User: not signed in.", {"Remote-Groups": "admin"}, error="unauthenticated",
        attack="header-missing-user")
    add("user-empty", "An empty Remote-User: not signed in.", {"Remote-User": "", "Remote-Groups": "admin"},
        error="unauthenticated", attack="header-missing-user")
    add("user-twice", "Remote-User twice (a proxy that appends instead of replacing).",
        {"Remote-User": ["anna", "admin"]}, error="header", attack="header-duplicate")
    add("groups-twice", "Remote-Groups twice in one request.", {"Remote-User": "anna", "Remote-Groups": ["editors", "admin"]},
        error="header", attack="header-duplicate")
    add("user-twice-case", "The same field twice under different spellings.",
        {"Remote-User": "anna", "remote-user": "admin"}, error="header", attack="header-duplicate")
    add("control-user", "A control character in Remote-User: refused, not stripped (`boss\\x01` must not become "
        "`boss`).", {"Remote-User": "boss\x01"}, error="header", attack="header-injection")
    add("control-name-tab", "A tab inside Remote-Name.", {"Remote-User": "anna", "Remote-Name": "Anna\tBerg"},
        error="header", attack="header-injection")
    add("groups-tab", "A tab is a control character, also next to a comma: refused, not trimmed.",
        {"Remote-User": "anna", "Remote-Groups": "editors\t,admin"}, error="header", attack="header-injection")
    add("invalid-utf8", "Remote-Name bytes that are no UTF-8.", {"Remote-User": "anna", "Remote-Name": "Anna \xff"},
        error="header", attack="header-encoding")
    add("overlong-utf8", "An overlong UTF-8 encoding of `/`.", {"Remote-User": "a\xc0\xafb"}, error="header",
        attack="header-encoding")
    add("id-not-digits", "Remote-Id is the decimal account ID.", {"Remote-User": "anna", "Remote-Id": "1 OR 1=1"},
        error="header", attack="id-format")
    add("id-arabic-digits", "Arabic-Indic digits are no ASCII digits.",
        {"Remote-User": "anna", "Remote-Id": "١".encode("utf-8").decode("latin-1")}, error="header",
        attack="id-format")

    # --- Remote-Kind (spec v2): what the account is; always sent, refused when missing or malformed ---
    add("valid-kind-user", "Remote-Kind `user` with a browser session: a person.",
        {"Remote-User": "anna", "Remote-Auth": "session", "Remote-Kind": "user"},
        ident=ident("anna", auth="session", kind="session"), attack="remote-kind")
    add("valid-kind-service", "The headers /auth/forward sends for a service account's API key: Remote-Kind "
        "`service`, a token request.", p.headers("service", "apikey"),
        ident=ident("backup-bot", "Backup Bot", "", ["editors"], uid["service"], "apikey", "token", "service"),
        attack="remote-kind")
    add("valid-kind-service-oauth", "A paired service that acts as a service account: `oauth` with `service`.",
        {"Remote-User": "backup-bot", "Remote-Auth": "oauth", "Remote-Kind": "service"},
        ident=ident("backup-bot", auth="oauth", account_kind="service"), attack="remote-kind")
    add("valid-kind-user-oauth", "A paired service that acts as a person: the request comes from a machine "
        "(Remote-Auth `oauth`), the account is a person (`user`).",
        {"Remote-User": "anna", "Remote-Auth": "oauth", "Remote-Kind": "user"},
        ident=ident("anna", auth="oauth"), attack="remote-kind")
    sess = {"Remote-User": "anna", "Remote-Auth": "session"}
    tok = {"Remote-User": "backup-bot", "Remote-Auth": "apikey"}
    add("kind-missing", "No Remote-Kind: an older TinySesam or proxy template. Refused, never taken as `user` (the "
        "log may say: TinySesam/proxy older than spec v2?).", sess, error="header", attack="remote-kind",
        with_kind=False)
    add("kind-empty", "An empty Remote-Kind is no kind.", dict(sess, **{"Remote-Kind": ""}), error="header",
        attack="remote-kind")
    add("kind-upper-user", "`User` is not `user`: compared exactly.", dict(sess, **{"Remote-Kind": "User"}),
        error="header", attack="remote-kind")
    add("kind-upper-service", "`SERVICE` is not `service`.", dict(tok, **{"Remote-Kind": "SERVICE"}), error="header",
        attack="remote-kind")
    for value in ("admin", "machine", "human"):
        add(f"kind-unknown-{value}", f"`{value}` is no account kind: only `user` and `service` exist.",
            dict(sess, **{"Remote-Kind": value}), error="header", attack="remote-kind")
    add("kind-inner-space", "`us er` is no kind (no trimming inside a value).", dict(sess, **{"Remote-Kind": "us er"}),
        error="header", attack="remote-kind")
    add("kind-twice", "Remote-Kind twice (a proxy that appends the client's value to TinySesam's).",
        dict(sess, **{"Remote-Kind": ["user", "service"]}), error="header", attack="remote-kind")
    add("kind-twice-spelling", "Remote-Kind twice under two spellings.",
        dict(sess, **{"Remote-Kind": "user", "remote-kind": "service"}), error="header", attack="remote-kind")
    add("kind-control", "A NUL after `user`: refused, not stripped.", dict(sess, **{"Remote-Kind": "user\x00"}),
        error="header", attack="header-injection")
    add("kind-service-session", "`service` with Remote-Auth `session`: TinySesam never sends this (a service account "
        "has no session).", dict(sess, **{"Remote-Kind": "service"}), error="header", attack="remote-kind")
    add("kind-missing-no-user", "Neither Remote-User nor Remote-Kind (an anonymous request on a public share path): "
        "not signed in — `unauthenticated` comes first, never `header`.", {"Remote-Groups": "editors"},
        error="unauthenticated", attack="remote-kind", with_kind=False)
    return out


# ---------- JWKS ----------

def jwks_sets() -> list:
    out = []

    def add(vid, reason, doc, *, kids=None, error=None):
        exp = {"ok": False, "error": error} if error else {"ok": True, "kids": kids}
        out.append({"id": vid, "attack": "jwks-shape" if error else ("jwks-entry" if vid not in ("valid", "minimal-entry") else None),
                    "reason": reason, "input": {"jwks": doc}, "expected": exp})

    a, b = jwk("A"), jwk("B")

    def entry(**change):
        e = dict(a)
        for k, v in change.items():
            if v is None:
                e.pop(k, None)
            else:
                e[k] = v
        return e

    add("valid", "Active and previous key, as /auth/gate/jwks.json serves them.", jwks("A", "B"),
        kids=[kid("A"), kid("B")])
    add("minimal-entry", "alg and use are optional.", {"keys": [entry(alg=None, use=None)]}, kids=[kid("A")])
    for vid, e, why in (
            ("kty-rsa", entry(kty="RSA"), "kty RSA"),
            ("crv-x25519", entry(crv="X25519"), "crv X25519 is a key-agreement curve"),
            ("crv-ed448", entry(crv="Ed448"), "crv Ed448 is not this protocol's curve"),
            ("x-short", entry(x=b64u(_public("A")[:31]), kid=gate_kid(_public("A")[:31])),
             "x of 31 bytes (its kid computed over those bytes, so only the length is wrong)"),
            ("x-padded", entry(x=b64u(_public("A")) + "="), "x with padding"),
            ("alg-hs256", entry(alg="HS256"), "alg HS256"),
            ("use-enc", entry(use="enc"), "use enc"),
            ("key-ops-sign", entry(key_ops=["sign"]), "key_ops without verify"),
            ("private-d", entry(d=b64u(_seed("A"))), "private material `d` in a public set"),
            ("kid-mismatch", entry(kid=kid("B")), "a kid that is not the SHA-256 prefix of x"),
            ("kid-missing", entry(kid=None), "no kid"),
            ("x5u", entry(x5u="https://evil.example.com/cert.pem"), "x5u: no remote key material"),
    ):
        add(f"skip-{vid}", f"An entry with {why} is skipped; the others stay usable.", {"keys": [e, b]},
            kids=[kid("B")])
    add("duplicate-kid", "Two entries with the same kid make that kid unusable.", {"keys": [a, dict(a), b]},
        kids=[kid("B")])
    add("not-object", "The document is an array.", [a], error="jwks_invalid")
    add("keys-missing", "The document has no `keys` member.", {"key": [a]}, error="jwks_invalid")
    add("keys-not-list", "`keys` is an object, not an array.", {"keys": a}, error="jwks_invalid")
    add("too-many-keys", "More than 32 entries in one set.", {"keys": [b] * 33}, error="jwks_invalid")
    return out


def jwks_scenarios() -> list:
    out = []
    claims = {"user": "anna", "name": "Anna Berg", "email": "anna@example.com", "groups": "editors", "id": "1",
              "auth": "session", "kind": "user"}

    def tok(label, now, kid_override=None):
        t = issue(label, sub="1", claims=claims, now=now, jti=f"s-{label}-{now}")
        if kid_override is None:
            return t
        return signed(head(label, kid=kid_override), claims_of(t), label)

    def ok_resp(*labels, cc="max-age=300"):
        r = {"status": 200, "body": jwks(*labels)}
        if cc is not None:
            r["cache_control"] = cc
        return r

    def step(now, label="A", *, fetch=None, fetched=False, error=None, kid_override=None):
        s = {"now": now, "jws": tok(label, now, kid_override), "expect": {"fetched": fetched,
                                                                          "ok": error is None}}
        if error:
            s["expect"]["error"] = error
        if fetch is not None:
            s["fetch"] = fetch
        return s

    def add(vid, reason, steps):
        out.append({"id": vid, "attack": "jwks-cache", "reason": reason, "steps": steps})

    t0 = NOW
    fail = {"error": "timeout"}
    add("cold-start-failure-backoff", "The first fetch fails: fail closed at once (no waiting, no hang), no new attempt "
        "within 10 s, then a successful fetch.", [
            step(t0, fetch=fail, fetched=True, error="key_unavailable"),
            step(t0 + 1, error="key_unavailable"),
            step(t0 + 9, error="key_unavailable"),
            step(t0 + 10, fetch=ok_resp("A"), fetched=True)])
    add("fresh-cache", "A fetched set is fresh for its max-age; no fetch per request.", [
        step(t0, fetch=ok_resp("A"), fetched=True),
        step(t0 + 299),
        step(t0 + 300, fetch=ok_resp("A"), fetched=True)])
    add("default-freshness", "Without Cache-Control the set is fresh for 300 s.", [
        step(t0, fetch=ok_resp("A", cc=None), fetched=True),
        step(t0 + 299),
        step(t0 + 300, fetch=ok_resp("A", cc=None), fetched=True)])
    add("max-age-floor", "max-age=0 is raised to 60 s — no fetch per request.", [
        step(t0, fetch=ok_resp("A", cc="no-cache, max-age=0"), fetched=True),
        step(t0 + 59),
        step(t0 + 60, fetch=ok_resp("A"), fetched=True)])
    add("max-age-ceiling", "max-age=86400 is lowered to 3600 s — a rotation arrives within the hour.", [
        step(t0, fetch=ok_resp("A", cc="public, max-age=86400"), fetched=True),
        step(t0 + 3599),
        step(t0 + 3600, fetch=ok_resp("A"), fetched=True)])
    add("rotation-unknown-kid", "A token of a new key: an unknown kid triggers one fetch, at most every 10 s.", [
        step(t0, fetch=ok_resp("A"), fetched=True),
        step(t0 + 5, "B", error="kid"),
        step(t0 + 10, "B", fetch=ok_resp("A", "B"), fetched=True),
        step(t0 + 11, "A")])
    add("unknown-kid-flood", "Tokens with a kid that never appears cannot make the client fetch more than every 10 s.", [
        step(t0, fetch=ok_resp("A"), fetched=True),
        step(t0 + 10, "X", fetch=ok_resp("A"), fetched=True, error="kid"),
        step(t0 + 11, "X", error="kid"),
        step(t0 + 19, "X", error="kid"),
        step(t0 + 19, "A"),
        step(t0 + 20, "X", fetch=ok_resp("A"), fetched=True, error="kid")])
    ka = kid("A")
    add("invalid-kid-no-fetch", "A kid of the wrong form (a path, upper case, 15 or 17 hex digits) is refused before "
        "the key set is consulted and never triggers a fetch — with an empty cache, a fresh one or a stale one. With fixed "
        "keys such a kid looks like an unknown one (both `kid`); only the fetch tells them apart. A well-formed unknown "
        "kid does fetch, at most every 10 s.", [
            step(t0, kid_override="../keys", error="kid"),
            step(t0, kid_override=ka.upper(), error="kid"),
            step(t0, kid_override=ka[:15], error="kid"),
            step(t0, kid_override=ka + "0", error="kid"),
            step(t0 + 1, fetch=ok_resp("A"), fetched=True),
            step(t0 + 2, kid_override=ka.upper(), error="kid"),
            step(t0 + 11, kid_override=ka[:15], error="kid"),
            step(t0 + 12, "X", fetch=ok_resp("A"), fetched=True, error="kid"),
            step(t0 + 13, "X", error="kid"),
            step(t0 + 400, kid_override=ka + "0", error="kid"),
            step(t0 + 400, kid_override=ka.upper(), error="kid"),
            step(t0 + 401, fetch=ok_resp("A"), fetched=True)])
    add("stale-if-error", "A failed refresh keeps the last good set for up to 3600 s past its freshness, then the client "
        "fails closed.", [
            step(t0, fetch=ok_resp("A"), fetched=True),
            step(t0 + 300, fetch=fail, fetched=True),
            step(t0 + 305),
            step(t0 + 3899, fetch={"status": 503}, fetched=True),
            step(t0 + 3910, fetch=fail, fetched=True, error="key_unavailable")])
    add("bad-document-is-failure", "A body that is no JSON, or a set without one usable key, counts as a failed fetch: "
        "the last good set stays.", [
            step(t0, fetch=ok_resp("A"), fetched=True),
            step(t0 + 300, fetch={"status": 200, "body_text": "<html>maintenance</html>"}, fetched=True),
            step(t0 + 310, fetch={"status": 200, "body": {"keys": [dict(jwk("A"), kty="RSA")]}}, fetched=True),
            step(t0 + 320, fetch={"status": 200, "body": [jwk("A")]}, fetched=True),
            step(t0 + 330, fetch=ok_resp("A", "B"), fetched=True)])
    return out


# ---------- top bar ----------

def topbar_vectors(p: Probe) -> list:
    out = []

    def add(vid, reason, data, want, attack=None):
        out.append({"id": vid, "attack": attack, "reason": reason, "input": {"topbar": data},
                    "expected": {"ok": True, "topbar": want}})

    signed_out = {"brand": "Example", "signed_in": False, "name": None, "links": [], "menu_links": [],
                  "account": None, "admin_panel": None, "logout": None, "approvals": None}
    anna = p.topbar("anna")
    add("signed-in", "GET /auth/topbar.json for a signed-in account.", anna,
        {"brand": "Example", "signed_in": True, "name": "Anna Berg",
         "links": [{"title": "Wiki", "href": "https://app.example.com/wiki"}, {"title": "Files", "href": "/files/"}],
         "menu_links": [{"title": "My collections", "href": "/collections"}],
         "account": f"{ISSUER}/auth/account", "admin_panel": None, "logout": f"{ISSUER}/auth/logout",
         "approvals": None})
    admin = p.topbar("admin")
    add("admin", "The admin panel link is shown to an admin.", admin,
        dict(signed_out, signed_in=True, name="Admin", links=[{"title": "Wiki", "href": "https://app.example.com/wiki"},
                                                              {"title": "Files", "href": "/files/"}],
             menu_links=[{"title": "My collections", "href": "/collections"},
                         {"title": "App admin", "href": "https://app.example.com/admin"}],
             account=f"{ISSUER}/auth/account", admin_panel=f"{ISSUER}/auth/admin", logout=f"{ISSUER}/auth/logout"))
    add("signed-out", "No session: the brand only, no links.", p.topbar(None), signed_out)
    evil = json.loads(json.dumps(anna))
    evil["links"] = [{"title": "x", "href": "javascript:alert(1)"}, {"title": "y", "href": "//evil.example.com/"},
                     {"title": "z", "href": "data:text/html,<script>"}, {"title": "w", "href": "/\\evil.example.com"},
                     {"title": "v", "href": "https://ok.example.com/a b"}, {"title": 5, "href": "/a"},
                     {"title": "ok", "href": "/ok"}]
    evil["menu_links"] = [{"title": "m", "href": "javascript:void(0)"}, {"title": "n", "href": "//evil.example.com/"},
                          {"title": "o", "href": "/\\evil.example.com"}, {"title": "p", "href": "/menu\tok"},
                          {"title": None, "href": "/menu"}, {"title": "menu", "href": "/menu"}]
    evil["account"] = {"shown": True, "href": "JavaScript:alert(1)"}
    add("unsafe-hrefs", "Only http(s) URLs and paths starting with a single `/` are rendered; everything else is dropped "
        "— in `links` and in `menu_links` alike.",
        evil, dict(signed_out, signed_in=True, name="Anna Berg", links=[{"title": "ok", "href": "/ok"}],
                   menu_links=[{"title": "menu", "href": "/menu"}], logout=f"{ISSUER}/auth/logout"),
        attack="topbar-href")
    old = json.loads(json.dumps(anna))
    del old["menu_links"]
    add("menu-links-missing", "An answer of an older TinySesam without `menu_links`: no menu links, the rest as usual.",
        old, {"brand": "Example", "signed_in": True, "name": "Anna Berg",
              "links": [{"title": "Wiki", "href": "https://app.example.com/wiki"}, {"title": "Files", "href": "/files/"}],
              "menu_links": [], "account": f"{ISSUER}/auth/account", "admin_panel": None,
              "logout": f"{ISSUER}/auth/logout", "approvals": None}, attack="topbar-types")
    wrong = json.loads(json.dumps(anna))
    wrong["menu_links"] = {"title": "x", "href": "/x"}
    add("menu-links-not-list", "`menu_links` that is no list counts as none.", wrong,
        {"brand": "Example", "signed_in": True, "name": "Anna Berg",
         "links": [{"title": "Wiki", "href": "https://app.example.com/wiki"}, {"title": "Files", "href": "/files/"}],
         "menu_links": [], "account": f"{ISSUER}/auth/account", "admin_panel": None,
         "logout": f"{ISSUER}/auth/logout", "approvals": None}, attack="topbar-types")
    add("wrong-types", "signed_in as a string is no `true`: shown as signed out.",
        {"brand": "Example", "signed_in": "true", "name": "anna", "links": [], "account": None},
        signed_out, attack="topbar-types")
    add("not-object", "An answer that is no object: signed out without brand.", ["x"],
        dict(signed_out, brand=""), attack="topbar-types")
    return out


def topbar_approval_vectors(ap: "AccountProbe") -> list:
    """The optional member `approvals` of spec §8, from an installation with approvals switched on."""
    out = []

    def add(vid, reason, data, want, attack=None):
        out.append({"id": vid, "attack": attack, "reason": reason, "input": {"topbar": data},
                    "expected": {"ok": True, "topbar": want}})

    anna = ap.topbar()
    assert anna.get("approvals") == {"pending": 1, "href": f"{ISSUER}/auth/approvals"}, anna.get("approvals")
    plain = {"brand": "Example", "signed_in": True, "name": "Anna Berg", "links": [], "menu_links": [],
             "account": f"{ISSUER}/auth/account", "admin_panel": None, "logout": f"{ISSUER}/auth/logout",
             "approvals": None}
    add("approvals-pending", "GET /auth/topbar.json with approvals switched on: one approval waits for this account; "
        "the normalized result carries the number and the checked link.",
        anna, dict(plain, approvals={"pending": 1, "href": f"{ISSUER}/auth/approvals"}))
    zero = json.loads(json.dumps(anna))
    zero["approvals"]["pending"] = 0
    add("approvals-none-waiting", "Approvals switched on, nothing waiting: zero is a count, not a missing member.",
        zero, dict(plain, approvals={"pending": 0, "href": f"{ISSUER}/auth/approvals"}))
    for vid, reason, value in (
            ("approvals-unsafe-href", "An `approvals.href` that is no safe link drops the whole member.",
             {"pending": 1, "href": "javascript:alert(1)"}),
            ("approvals-protocol-relative", "A protocol-relative `approvals.href` drops the whole member.",
             {"pending": 1, "href": "//evil.example.com/auth/approvals"}),
            ("approvals-negative", "A negative `pending` is no count.", {"pending": -1, "href": "/auth/approvals"}),
            ("approvals-not-integer", "`pending` as a boolean is no count.",
             {"pending": True, "href": "/auth/approvals"}),
            ("approvals-string", "`pending` as a string is no count.", {"pending": "1", "href": "/auth/approvals"}),
            ("approvals-fraction", "`pending` with a fraction is no count.",
             {"pending": 1.5, "href": "/auth/approvals"}),
            ("approvals-no-href", "Without an `href` there is nowhere to decide: no member.", {"pending": 1}),
            ("approvals-not-object", "`approvals` that is no object counts as none.", [1, "/auth/approvals"])):
        bad = json.loads(json.dumps(anna))
        bad["approvals"] = value
        add(vid, reason, bad, plain, attack="topbar-href" if "href" in vid or "relative" in vid else "topbar-types")
    out_ = json.loads(json.dumps(anna))
    out_["signed_in"] = False
    add("approvals-signed-out", "Signed out: no approvals, whatever the answer says.", out_,
        {"brand": "Example", "signed_in": False, "name": None, "links": [], "menu_links": [], "account": None,
         "admin_panel": None, "logout": None, "approvals": None}, attack="topbar-types")
    return out


# ---------- the own account as data (spec §8a) ----------

class AccountProbe:
    """A throwaway TinySesam with approvals, TOTP, PIN, passkeys and API keys switched on, and the person `anna` with
    some of each — under a fixed clock, so the answer of `/auth/account.json` is the same on every run."""

    APP = "example"

    def __init__(self):
        from tinysesam import TinySesam, TinySesamConfig
        self.dir = tempfile.mkdtemp(prefix="tinysesam-account-vectors-")
        with self.clock(), open(os.devnull, "w") as quiet, contextlib.redirect_stderr(quiet):
            self.auth = TinySesam(TinySesamConfig(
                db_path=os.path.join(self.dir, "probe.db"), base_url=ISSUER, rp_name="Example", oidc_enabled=False,
                passkey_enabled=True, totp_enabled=True, pin_enabled=True, apikey_enabled=True,
                approvals_enabled=True, forward_auth_enabled=True,
                forward_apps={"dav.example.com": {"app_passwords": True}},
                apps={self.APP: {"account": "svc-example", "name": {"en": "Example"},
                                 "approvals": {"types": {"example.collection.archive": {
                                     "fields": {"collection": {"type": "string", "max": 64}},
                                     "title": {"en": "Archive a collection", "de": "Collection archivieren"},
                                     "summary": {"en": "Archive {collection}.", "de": "{collection} archivieren."}}},
                                     "return_urls": ["https://app.example.com/approvals/return"]}}}))
            a = self.auth
            self.service = a.create_service("svc-example")
            self.anna = a.create_user("anna", "a long probe password 4711", display_name="Anna Berg")
            uid = int(self.anna)
            a.store.set_totp(uid, "JBSWY3DPEHPK3PXP", confirmed=True)
            a.store.add_recovery_codes(uid, ["hash-1", "hash-2"])
            a.store.add_webauthn(uid, b"credential-1", b"public-key", 0, ["usb"], "Security key")
            a.store.set_pin_hash(uid, "pin-hash")
            a.store.create_session(uid, 3600, 1, "password", ua="Mozilla/5.0 (X11; Linux x86_64; rv:140.0) "
                                                               "Gecko/20100101 Firefox/140.0")
            a.store.create_session(uid, 3600, 1, "passkey", ua="")
            # The session handles (T-105) are random; fixed ones keep the vectors reproducible.
            a.store._exec("UPDATE session_handle SET handle = printf('%032x', rowid)")
            a.store.add_api_key(uid, "backup", "tsk_probe", "key-hash")
            a.create_app_password(uid, "Phone calendar", expires_days=30)
            from tinysesam import approvals as apv
            text = apv.canonical({"type": "example.collection.archive", "collection": "c_81f2"})
            a.store.add_approval({
                "id": "apv_probe", "class": "app", "type": "example.collection.archive", "app_id": self.APP,
                "subject_id": uid, "requester_kind": "app", "requester_ref": str(int(self.service)),
                "payload": text, "payload_hash": apv.payload_hash(text), "match_code": "418 207", "return_url": None,
                "nonce": None, "state": "pending", "created_at": NOW - 30, "expires_at": NOW + 300,
                "decided_at": None, "stepup_amr": None, "auth_time": None})

    @staticmethod
    @contextlib.contextmanager
    def clock():
        """Every clock the probe's data passes through, fixed at NOW."""
        from tinysesam import approvals as apv
        from tinysesam import manager
        from tinysesam import store as store_mod
        saved = (store_mod._now, apv._now, manager._wall_now, manager._now)
        store_mod._now = apv._now = manager._wall_now = manager._now = lambda: NOW
        try:
            yield
        finally:
            store_mod._now, apv._now, manager._wall_now, manager._now = saved

    def close(self) -> None:
        import shutil
        self.auth.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def user(self) -> dict:
        u = dict(self.auth.get_user(self.anna))
        u["_via"] = "session"
        return u

    def topbar(self) -> dict:
        with self.clock():
            return self.auth.topbar_data(self.user(), base=ISSUER)

    def answer(self, **off) -> dict:
        """The body of `GET /auth/account.json` (`router._account_json`): `signed_in` plus `account_overview`. `off`
        switches configuration fields for this one answer (an installation that offers less)."""
        cfg = self.auth.cfg
        saved = {k: getattr(cfg, k) for k in off}
        for k, v in off.items():
            setattr(cfg, k, v)
        try:
            with self.clock():
                view = self.auth.account_overview(self.user(), base=ISSUER)
        finally:
            for k, v in saved.items():
                setattr(cfg, k, v)
        assert view is not None
        return {"signed_in": True, **view}


#: The members of the normalized account overview (spec §8a) — every one present in every signed-in result.
ACCOUNT_LINKS = ("account", "sessions", "totp", "passkeys", "devices", "app_passwords", "services", "approvals")
SIGNED_OUT_ACCOUNT = {"signed_in": False, "account": None, "sign_in": None, "sessions": None, "programs": None,
                      "approvals": None, "permissions": None, "links": None}
#: Members of TinySesam's answer a helper does not normalize (spec §8a): it drops them like any unknown member — of
#: the answer, and of every session (the session handle and the address of the action page that ends it, T-105).
ACCOUNT_UNNORMALIZED = ("actions",)
SESSION_UNNORMALIZED = ("handle", "end")


def _drop_unnormalized(answer: dict) -> None:
    for member in ACCOUNT_UNNORMALIZED:
        del answer[member]
    for item in answer["sessions"]["items"]:
        for member in SESSION_UNNORMALIZED:
            del item[member]


def account_vectors(ap: AccountProbe) -> list:
    import copy
    out = []

    def add(vid, reason, data, want, attack=None):
        out.append({"id": vid, "attack": attack, "reason": reason, "input": {"account": data},
                    "expected": {"ok": True, "account": want}})

    full = ap.answer()
    # The server's answer has exactly the members this file knows: a new member needs a decision here (and in §8a).
    # `actions` (§8c, T-105) is a member the helpers do not normalize yet: the browser follows its addresses itself.
    assert sorted(full) == sorted([*SIGNED_OUT_ACCOUNT, *ACCOUNT_UNNORMALIZED]), sorted(full)
    assert all(v is None or v.startswith(f"{ISSUER}/auth/act/") for v in full["actions"].values()), full["actions"]
    raw = copy.deepcopy(full)
    _drop_unnormalized(full)
    assert sorted(full["links"]) == sorted(ACCOUNT_LINKS), sorted(full["links"])
    s = full["sessions"]["items"]
    assert full["sign_in"]["password"] == "set" and full["sign_in"]["totp"]["enabled"] is True, full["sign_in"]
    assert full["approvals"] == {"pending": 1} and full["programs"]["api_keys_active"] == 1, full
    assert len(s) == 2 and s[0]["device"] is not None and s[1]["device"] is None, s
    assert full["account"]["source"] == ["local"], full["account"]
    assert [p["name"] for p in full["programs"]["app_passwords"]] == ["Phone calendar"], full["programs"]
    # Valid and complete: the normalized form IS the answer (every href safe, every member of its type) — without the
    # member `actions`, which a helper drops like every member it does not normalize.
    add("signed-in", "GET /auth/account.json for a person with password, TOTP, a passkey, a PIN, two sessions, an API "
        "key and one approval waiting; its `actions` (spec §8c) and the sessions' `handle` and `end` are not "
        "normalized and dropped.", raw,
        copy.deepcopy(full))
    less = ap.answer(totp_enabled=False, pin_enabled=False, passkey_enabled=False, apikey_enabled=False,
                     approvals_enabled=False, account_enabled=False)
    _drop_unnormalized(less)
    assert less["sign_in"]["totp"] is None and less["links"]["account"] is None, less
    add("offered-less", "An installation without TOTP, PIN, passkeys, API keys, approvals and account page: `null` "
        "means not offered here.", less, copy.deepcopy(less))
    add("signed-out-401", "The body of the 401 answer: signed out.", {"authenticated": False, "signed_in": False},
        SIGNED_OUT_ACCOUNT)
    add("signed-in-string", "`signed_in` as a string is no `true`: signed out.", dict(full, signed_in="true"),
        SIGNED_OUT_ACCOUNT, attack="account-types")
    add("not-object", "An answer that is no object: signed out.", [full], SIGNED_OUT_ACCOUNT, attack="account-types")

    evil = copy.deepcopy(full)
    evil["account"]["display_name"] = "<img src=x onerror=alert(1)>"
    evil["links"].update(account="javascript:alert(1)", sessions="//evil.example.com/a", totp="/\\evil.example.com",
                         passkeys="data:text/html,<script>", devices="https://ok.example.com/a b",
                         app_passwords="/x\x07", services=5, approvals="/auth/approvals")
    want = copy.deepcopy(full)
    want["account"]["display_name"] = "<img src=x onerror=alert(1)>"
    want["links"] = {k: None for k in ACCOUNT_LINKS}
    want["links"]["approvals"] = "/auth/approvals"
    add("unsafe-hrefs", "Only http(s) URLs and paths starting with a single `/` survive, every other `href` becomes "
        "`null`; a name with markup stays text, unchanged.", evil, want, attack="account-href")

    wrong = copy.deepcopy(full)
    wrong["account"]["username"] = 5
    wrong["sign_in"]["password"] = True
    wrong["sign_in"]["totp"] = {"enabled": "yes", "recovery_left": -1, "recovery_low": 1}
    wrong["sign_in"]["passkeys"] = {"count": 1.5, "items": {"name": "x"}}
    wrong["sign_in"]["pin"] = "true"
    wrong["sessions"] = {"count": "2", "items": ["x", {"created_at": "1", "last_seen": True, "method": 7,
                                                        "device": ["a"], "current": "yes"}]}
    wrong["programs"] = {"oauth": {"name": "x"}, "services": "none", "app_passwords": [None],
                         "api_keys_active": False}
    wrong["approvals"] = {"pending": -1}
    want = copy.deepcopy(full)
    want["account"]["username"] = None
    want["sign_in"] = {"password": None, "totp": {"enabled": None, "recovery_left": None, "recovery_low": None},
                       "passkeys": {"count": None, "items": []}, "pin": None}
    want["sessions"] = {"count": None, "items": [{"created_at": None, "last_seen": None, "method": None,
                                                  "device": None, "current": None}]}
    want["programs"] = {"oauth": None, "services": None, "app_passwords": [], "api_keys_active": None}
    want["approvals"] = None
    add("wrong-types", "A member of the wrong type reads as missing (`null`); an entry of a list that is no object is "
        "dropped; a negative count is no count.", wrong, want, attack="account-types")

    grown = copy.deepcopy(full)
    grown["recovery"] = {"email": "anna@example.com"}
    grown["sign_in"]["password_age_days"] = 12
    grown["sessions"]["items"][0]["ip"] = "192.0.2.1"
    grown["links"]["security_log"] = "/auth/account#log"
    del grown["programs"]
    want = copy.deepcopy(full)
    want["programs"] = {"oauth": None, "services": None, "app_passwords": None, "api_keys_active": None}
    add("unknown-and-missing", "Members a newer TinySesam adds are ignored; a missing group reads as all `null`.",
        grown, want, attack="account-types")
    groups = dict(full, account="anna", sign_in=5, sessions=True, programs=["x"], links="/auth/account")
    add("groups-wrong-type", "A group of the wrong type (a string, a number, a boolean, a list) reads as an empty one: "
        "every member `null`, the lists empty.", groups,
        {"signed_in": True, "account": {"username": None, "display_name": None, "source": None},
         "sign_in": {"password": None, "totp": None, "passkeys": None, "pin": None},
         "sessions": {"count": None, "items": []},
         "programs": {"oauth": None, "services": None, "app_passwords": None, "api_keys_active": None},
         "approvals": copy.deepcopy(full["approvals"]), "permissions": None, "links": {k: None for k in ACCOUNT_LINKS}},
        attack="account-types")
    mixed = copy.deepcopy(full)
    mixed["account"]["source"] = ["local", 5, None, "oidc", ["saml"], "scim"]
    want = copy.deepcopy(full)
    want["account"]["source"] = ["local", "oidc", "scim"]
    add("source-entries", "`account.source` is a list of texts (`local`, `oidc`, `saml`, `ldap`; two or more = a mixed "
        "account): an entry that is no string is dropped, an unknown text stays for the application to ignore.", mixed,
        want, attack="account-types")
    one = copy.deepcopy(full)
    one["account"]["source"] = "local"
    want = copy.deepcopy(full)
    want["account"]["source"] = None
    add("source-not-list", "`account.source` as a single string is no list: `null`.", one, want, attack="account-types")
    bool_pending = copy.deepcopy(full)
    bool_pending["approvals"] = {"pending": True}
    want = copy.deepcopy(full)
    want["approvals"] = None
    add("approvals-not-integer", "`approvals.pending` must be an integer, a boolean is none.", bool_pending, want,
        attack="account-types")
    # §8a `permissions` (T-101): `null` off an application's host (the probe's own answer above), the object on one.
    assert full["permissions"] is None, "the probe's answer names permissions without an application host"
    on_app = copy.deepcopy(full)
    on_app["permissions"] = {"app": "docs", "names": ["docs.delete", "docs.read"]}
    add("permissions-on-app-host", "On an application's host the answer names the application and the account's "
        "permissions for it.", on_app, copy.deepcopy(on_app))
    wrong = copy.deepcopy(full)
    wrong["permissions"] = {"app": 7, "names": ["docs.read", 1, None, {"x": 1}], "extra": True}
    want = copy.deepcopy(full)
    want["permissions"] = {"app": None, "names": ["docs.read"]}
    add("permissions-wrong-types", "An `app` that is no text reads as null, an entry of `names` that is no string is "
        "dropped, an unknown member too.", wrong, want, attack="account-types")
    no_list = copy.deepcopy(full)
    no_list["permissions"] = {"app": "docs", "names": "docs.read"}
    want = copy.deepcopy(full)
    want["permissions"] = {"app": "docs", "names": []}
    add("permissions-names-not-list", "`names` that is no list reads as an empty list.", no_list, want,
        attack="account-types")
    not_object = copy.deepcopy(full)
    not_object["permissions"] = ["docs.read"]
    add("permissions-not-object", "`permissions` that is no object reads as null.", not_object, copy.deepcopy(full),
        attack="account-types")
    return out


# ---------- files ----------

def _file(kind: str, body: dict) -> str:
    doc = {"format": FORMAT, "kind": kind,
           "spec": "spec/gate-client.md",
           "generated_by": "scripts/_gate_vectors.py — do not edit by hand",
           "defaults": {"issuer": ISSUER, "audience": AUDIENCE, "now": NOW}}
    doc.update(body)
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def build() -> dict:
    """File name → content of every vector file."""
    p = Probe()
    keys = {"_test_material": "TEST KEYS ONLY. The private seeds are derived from a public label and printed here so "
                              "that client authors can mint further test tokens. Never use them anywhere else.",
            "keys": {label: {"role": role, "seed_label": f"tinysesam gate-client test vector key {label}",
                             "d": b64u(_seed(label)), "public_jwk": jwk(label),
                             "sign_key_base64": base64.b64encode(_public(label)).decode("ascii")}
                     for label, role in (("A", "active gate key of the probe installation"),
                                         ("B", "previous key after a rotation"),
                                         ("X", "the attacker's key, in no key set"))}}
    ap = AccountProbe()
    try:
        return {
            "keys.json": _file("keys", keys),
            "token.json": _file("token", {"vectors": token_vectors(p)}),
            "headers.json": _file("headers", {"vectors": header_vectors(p)}),
            "jwks.json": _file("jwks", {"sets": jwks_sets(), "scenarios": jwks_scenarios()}),
            "topbar.json": _file("topbar", {"vectors": topbar_vectors(p) + topbar_approval_vectors(ap)}),
            "account.json": _file("account", {"vectors": account_vectors(ap)}),
            # Last: it names the probe's host as an application for a moment (and assigns two permissions).
            "permissions.json": _file("permissions", permission_vectors(p)),
        }
    finally:
        p.close()
        ap.close()


# ---------- permissions, spec §3.4 (T-101) ----------

PERM_APP = "docs"
PERM_MANIFEST = [{"name": "docs.read", "label": {"en": "Read documents", "de": "Dokumente lesen"}},
                 {"name": "docs.delete", "label": {"en": "Delete documents"}, "danger": True}]


def permission_vectors(p: Probe) -> dict:
    """`headers`, `tokens` and `register`. The valid inputs come from TinySesam's own paths with the probe's host
    named as the application `docs` for this file only (the other files stay without permissions)."""
    a = p.auth
    saved = (a.cfg.apps, a.cfg.available_roles)
    a.cfg.apps = {PERM_APP: {"name": "Documents", "hosts": [AUDIENCE], "permissions": PERM_MANIFEST}}
    a.cfg.available_roles = ["editors", "reviewers", "readers"]
    try:
        a._register_config_permissions()
        a.grant_permission("editors", "docs.read", app=PERM_APP)
        a.grant_permission("reviewers", "docs.delete", app=PERM_APP)
        juergen_headers = p.headers("juergen", host=AUDIENCE)
        anna_headers = p.headers("anna", host=AUDIENCE)
        admin_headers = p.headers("admin", host=AUDIENCE)
        juergen_token = p.token("juergen", jti="perm")
        admin_token = p.token("admin", jti="perm-admin")
    finally:
        a.cfg.apps, a.cfg.available_roles = saved
    assert juergen_headers["Remote-Permissions"] == "docs.delete,docs.read", juergen_headers
    assert anna_headers["Remote-Permissions"] == "docs.read" and admin_headers["Remote-Permissions"] == ""
    assert claims_of(juergen_token)["ts_perms"] == "docs.delete,docs.read"
    guards_full = {"docs.read": True, "docs.delete": True, "docs.share": False, "Docs.read": False, "docs": False,
                   "docs.read ": False}

    headers_out: list = []

    def h(vid, reason, headers, *, perms=None, guards=None, error=None, attack=None):
        if not any(k.lower() == "remote-kind" for k in headers):
            headers = dict(headers, **{"Remote-Kind": "user"})
        exp = {"ok": False, "error": error} if error else {"ok": True, "permissions": perms}
        if guards:
            exp["has_permission"] = guards
        headers_out.append({"id": vid, "attack": attack, "reason": reason, "input": {"headers": headers},
                            "expected": exp})

    base = {"Remote-User": "anna", "Remote-Id": str(p.users["anna"]), "Remote-Auth": "session"}
    h("valid", "The headers /auth/forward sends on the application's host: the union over two roles, sorted.",
      juergen_headers, perms=["docs.delete", "docs.read"], guards=guards_full)
    h("valid-one", "One role, one permission.", anna_headers, perms=["docs.read"],
      guards={"docs.read": True, "docs.delete": False})
    h("admin-holds-none", "The admin flag implies no permission: TinySesam sends none, the client implies none.",
      admin_headers, perms=[], guards={"docs.read": False, "admin": False}, attack="permissions-parsing")
    h("missing", "No Remote-Permissions at all (a host of no application, an older TinySesam): no permissions, no "
      "error.", base, perms=[], guards={"docs.read": False})
    h("parsing", "Spaces, empty and repeated entries are read like the groups (§3.3).",
      dict(base, **{"Remote-Permissions": " docs.read, docs.read,,docs.delete , "}),
      perms=["docs.read", "docs.delete"], guards={"docs.read": True, "docs.delete": True},
      attack="permissions-parsing")
    h("case-and-prefix", "Exact comparison: another case is another name, a prefix is no wildcard.",
      dict(base, **{"Remote-Permissions": "DOCS.READ,docs"}), perms=["DOCS.READ", "docs"],
      guards={"docs.read": False, "docs.delete": False, "docs": True}, attack="permissions-parsing")
    h("twice", "Remote-Permissions twice: an error, never joined or picked.",
      dict(base, **{"Remote-Permissions": ["docs.read", "docs.delete"]}), error="header",
      attack="permissions-header")
    h("twice-spelling", "Remote-Permissions twice in two spellings.",
      dict(base, **{"Remote-Permissions": "docs.read", "remote-permissions": "docs.delete"}), error="header",
      attack="permissions-header")
    h("control", "A control character in Remote-Permissions is refused, not stripped.",
      dict(base, **{"Remote-Permissions": "docs.read\x01"}), error="header", attack="permissions-header")
    h("invalid-utf8", "Invalid UTF-8 in Remote-Permissions.",
      dict(base, **{"Remote-Permissions": "docs.read\xc3"}), error="header", attack="permissions-header")

    tokens_out: list = []

    def t(vid, reason, jws, *, perms=None, guards=None, error=None, attack=None):
        exp = {"ok": False, "error": error} if error else {"ok": True, "permissions": perms}
        if guards:
            exp["has_permission"] = guards
        tokens_out.append({"id": vid, "attack": attack, "reason": reason,
                           "input": {"jws": jws, "now": NOW + 10, "leeway": 0, "issuer": ISSUER,
                                     "audience": AUDIENCE, "jwks": jwks("A")}, "expected": exp})

    ident = {"user": "anna", "groups": "editors", "id": str(p.users["anna"]), "auth": "session", "kind": "user"}
    t("token-valid", "The gate token /auth/forward issues on the application's host: ts_perms.", juergen_token,
      perms=["docs.delete", "docs.read"], guards=guards_full)
    t("token-admin-holds-none", "The admin flag implies no permission.", admin_token, perms=[],
      guards={"docs.read": False}, attack="permissions-parsing")
    t("token-missing", "A token without ts_perms (issued before the update, a reduced forward_headers): none.",
      issue("A", sub=str(p.users["anna"]), claims=ident, jti="perm-missing"), perms=[], guards={"docs.read": False})
    t("token-type", "ts_perms as a list is the wrong type.",
      issue("A", sub=str(p.users["anna"]), claims=dict(ident, perms=["docs.read"]), jti="perm-type"),
      error="claims", attack="permissions-header")
    t("token-control", "A line break in ts_perms is refused, not stripped.",
      issue("A", sub=str(p.users["anna"]), claims=dict(ident, perms="docs.read\ndocs.delete"), jti="perm-ctl"),
      error="claims", attack="permissions-header")

    register_out: list = []
    one = [PERM_MANIFEST[0]]

    def r(vid, reason, base_url, app, perms, *, url=None, attack=None):
        exp = {"ok": True, "request": {"method": "PUT", "url": url, "body": {"permissions": perms}}} if url else \
            {"ok": False, "error": "invalid"}
        register_out.append({"id": vid, "attack": attack, "reason": reason,
                             "input": {"base_url": base_url, "app": app, "permissions": perms}, "expected": exp})

    r("register", "The whole manifest as the body of a PUT, straight to TinySesam.", ISSUER, PERM_APP, PERM_MANIFEST,
      url=f"{ISSUER}/auth/api/apps/{PERM_APP}/permissions")
    r("register-trailing-slash", "A trailing slash of the base URL is not doubled.", ISSUER + "/", PERM_APP, one,
      url=f"{ISSUER}/auth/api/apps/{PERM_APP}/permissions")
    r("register-loopback-http", "Plain http only to a loopback address.", "http://127.0.0.1:8000", PERM_APP, one,
      url=f"http://127.0.0.1:8000/auth/api/apps/{PERM_APP}/permissions")
    r("register-empty", "An empty manifest orphans every name the application registered before.", ISSUER, PERM_APP,
      [], url=f"{ISSUER}/auth/api/apps/{PERM_APP}/permissions")
    r("register-http", "Plain http to another host is refused.", "http://auth.example.com", PERM_APP, one,
      attack="register-manifest")
    r("register-app-id", "An application id outside the rule (upper case).", ISSUER, "Docs", one,
      attack="register-manifest")
    r("register-app-path", "An application id with a path in it.", ISSUER, "docs/../admin", one,
      attack="register-manifest")
    for vid, name in (("register-name-case", "Docs.read"), ("register-name-no-dot", "docs"),
                      ("register-name-space", "docs.read "), ("register-name-five", "a.b.c.d.e")):
        r(vid, f"A name outside the rule: {name!r}.", ISSUER, PERM_APP, [{"name": name}], attack="register-manifest")
    r("register-name-missing", "An entry without a name.", ISSUER, PERM_APP, [{"label": "x"}],
      attack="register-manifest")
    r("register-entry-type", "An entry that is no object.", ISSUER, PERM_APP, ["docs.read"],
      attack="register-manifest")
    r("register-twice", "A name twice.", ISSUER, PERM_APP, one + one, attack="register-manifest")
    r("register-too-many", "More than 200 entries.", ISSUER, PERM_APP,
      [{"name": f"docs.p{i}"} for i in range(201)], attack="register-manifest")
    r("register-not-list", "A manifest that is no list.", ISSUER, PERM_APP, {"permissions": one},
      attack="register-manifest")
    return {"headers": headers_out, "tokens": tokens_out, "register": register_out}


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def main(argv) -> int:
    files = build()
    if "--check" in argv:
        stale = []
        for name, text in files.items():
            path = os.path.join(OUT, name)
            if not os.path.exists(path) or _read(path) != text:
                stale.append(name)
        if stale:
            print("stale gate vectors: " + ", ".join(stale) + " — run python scripts/_gate_vectors.py", file=sys.stderr)
            return 1
        print(f"gate vectors current ({len(files)} files)")
        return 0
    os.makedirs(OUT, exist_ok=True)
    for name, text in files.items():
        with open(os.path.join(OUT, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    print(f"wrote {len(files)} files to spec/vectors/")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

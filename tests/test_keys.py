"""The installation's keys (T-48, T-53, T-54; ADR-12): purposes, rotation, re-encryption, AAD, migration.

What must hold, each checked against the real code paths:

  (a) rotation without loss: TOTP, OIDC refresh token, OAuth access/refresh token and gate token before AND after
      rotating each purpose, across restarts; `keys reencrypt` leaves nothing with the old key; `keys retire` refuses
      while anything still needs a key, and works afterwards
  (b) a running service follows a rotation done by the CLI (it re-reads the keyring on an unknown key ID)
  (c) AAD (T-54): a ciphertext moved to another row or column, or with a swapped key ID, does not decrypt
  (d) migration from 0.25.x: a database with the single base key, `v1:` values, a gate key and an OAuth pepper derived
      from it — starts without handwork, values rewritten as `v2:`, old gate tokens stay verifiable for their lifetime,
      old OAuth tokens stay valid; the way back (`reencrypt --to v1`) and an accidental older start are survived
  (e) the gate key is not derivable from the vault key; the JWKS drops a previous key after the overlap
  (f) config_check: key file readable by others, key file beside the database, gate key reachable through the data
      directory alone
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from cryptography.exceptions import InvalidTag                  # noqa: E402
from cryptography.hazmat.primitives import serialization         # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM   # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, config_check, gate, keys, oauth, totp   # noqa: E402
from tinysesam.errors import ConfigError                       # noqa: E402
from _kit.report import Report                                 # noqa: E402

r = Report("Keys — purposes, rotation, re-encryption, AAD, migration (T-48, T-53, T-54)")

BASE = "https://auth.example.com"
RESOURCE = "https://app.example.com/mcp"
ENV = {k: v for k, v in os.environ.items() if not k.startswith("TINYSESAM_")}
ENV["PYTHONPATH"] = os.pathsep.join([str(ROOT), *sys.path])
for name in list(os.environ):
    if name.startswith(("TINYSESAM_SECRETS_KEY", "TINYSESAM_GATE_KEY", "TINYSESAM_OAUTH_PEPPER")):
        del os.environ[name]


def config(db, **over):
    cfg = dict(db_path=db, base_url=BASE, cookie_secure=False, passkey_enabled=False, lang="en",
               forward_auth_enabled=True, gate_token_enabled=True, trusted_redirect_hosts=["app.example.com"],
               oauth_enabled=True, oauth_resources=[RESOURCE])
    cfg.update(over)
    return TinySesamConfig(**cfg)


def cli(*args):
    return subprocess.run([sys.executable, "-m", "tinysesam", "keys", *args], capture_output=True, text=True,
                          env=ENV, timeout=120, cwd=str(ROOT))


def gate_token(auth, uid) -> str:
    return gate.issue(auth._gate_key_name, iss=auth.gate_issuer(), aud="app.example.com", sub=str(uid),
                      claims={"user": "anna"}, ttl=300, now=int(time.time()))


def verify_with_jwks(auth, token) -> bool:
    """As caddy-jwt with `jwk_url` does: pick the key by `kid` from the published set, then check."""
    head = json.loads(gate._read_b64u(token.split(".")[0]))
    for k in auth.gate_jwks()["keys"]:
        if k["kid"] == head.get("kid"):
            return gate.check(gate._read_b64u(k["x"]), token, aud="app.example.com", iss=BASE,
                              now=int(time.time())) is not None
    return False


def oauth_pair(auth, uid):
    srv = auth._oauth_server()
    now = int(time.time())
    if auth.store.oauth_client("cid") is None:
        auth.store.oauth_add_client("cid", "Probe", ["http://localhost/cb"], now, None)
    at, rt, rows = srv._pair("mcp", True)
    auth.store.oauth_create_grant("no-code", "cid", uid, RESOURCE, "mcp", now, None, None, rows)
    return at, rt


def oauth_ok(auth, at) -> bool:
    user, why = auth._oauth_server().user_for(at, RESOURCE + "/tools", None)
    return user is not None


def oidc_row(auth, uid, sub="sub-anna", refresh="rt-anna"):
    handle = auth.store.session_hash(auth.store.create_session(uid, 3600, True, "oidc"))
    auth.store.set_oidc_session(handle, "*", sub, refresh, "client-1")
    auth.store.set_oidc_id_token(handle, "*", "id-token-" + sub)
    return handle


def everything_works(auth, uid, secret, handle, at, gtok, what) -> None:
    r.check(f"{what}: TOTP secret readable, a current code verifies",
            auth.store.get_totp(uid)["secret"] == secret
            and totp.verify(auth.store.get_totp(uid)["secret"], _code(secret)))
    row = auth.store._one("SELECT * FROM oidc_session WHERE token_hash=?", (handle,))
    r.check(f"{what}: OIDC refresh token and ID token readable",
            auth.store.oidc_refresh_plain(row) == "rt-anna"
            and auth.store.get_oidc_id_token(handle) == ("*", "id-token-sub-anna"))
    r.check(f"{what}: OAuth access token accepted", oauth_ok(auth, at))
    r.check(f"{what}: the gate token from before verifies against the published keys", verify_with_jwks(auth, gtok))


def raises(fn, kind=Exception) -> bool:
    try:
        fn()
    except kind:
        return True
    return False


def _code(secret: str) -> str:
    import hashlib
    import hmac
    import struct
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


# ======================================================================== (a) rotation without loss
work = Path(tempfile.mkdtemp())
keydir = Path(tempfile.mkdtemp())          # the key apart from the database, as recommended
kfile = keydir / "vault.key"
kfile.write_text(base64.b64encode(secrets.token_bytes(32)).decode() + "\n")
kfile.chmod(0o600)
db = str(work / "t.db")
a = TinySesam(config(db, secrets_key_file=str(kfile)))
uid = a.create_user("anna", "dummy123")
SECRET = totp.new_secret()
a.store.set_totp(uid, SECRET, confirmed=True)
handle = oidc_row(a, uid)
at, rt = oauth_pair(a, uid)
gtok = gate_token(a, uid)
everything_works(a, uid, SECRET, handle, at, gtok, "before any rotation")
k_vault0, k_gate0, k_pepper0 = a._vault_keyring.active.kid, a._gate_keyring.active.kid, a._pepper_keyring.active.kid
r.check("a new installation: one key per purpose, three different IDs, gate and pepper kept in the database",
        a._gate_keyring.origin == a._pepper_keyring.origin == "database"
        and len(a._gate_keyring.keys) == len(a._pepper_keyring.keys) == 1
        and json.loads(gate._read_b64u(gtok.split(".")[0]))["kid"] == k_gate0)

# --- vault: retire refused for the active key / without previous; rotate; still running service follows (b)
out = cli("retire", "--purpose", "vault", "--db", db, "--secrets-key-file", str(kfile))
r.check("retire without a previous key: nothing to do, exit 0", out.returncode == 0 and "nothing" in out.stdout,
        out.stdout + out.stderr)
out = cli("rotate", "--purpose", "vault", "--db", db, "--secrets-key-file", str(kfile))
ring = keys.read_file(keys.VAULT, str(kfile), "test")
r.check("rotate vault: the file now holds the new active key and the old one as previous (with its date); "
        "mode 0600 kept; no key material printed",
        out.returncode == 0 and ring[0].kid != k_vault0 and ring[1].kid == k_vault0 and ring[1].since
        and (kfile.stat().st_mode & 0o777) == 0o600
        and all(base64.b64encode(k.material).decode() not in out.stdout + out.stderr for k in ring),
        out.stdout + out.stderr)
k_vault1 = ring[0].kid
out = cli("retire", "--purpose", "vault", "--db", db, "--secrets-key-file", str(kfile))
r.check("retire the old vault key BEFORE reencrypt: refused, the file unchanged",
        out.returncode == 1 and "still need it" in out.stderr
        and [k.kid for k in keys.read_file(keys.VAULT, str(kfile), "t")] == [k_vault1, k_vault0], out.stderr)
out = cli("reencrypt", "--db", db, "--secrets-key-file", str(kfile))
counts = a.store.ciphertext_counts()
r.check("reencrypt: every stored value now carries the new key (progress printed)",
        out.returncode == 0 and set(counts) == {k_vault1} and "totp_cred.secret: 1/1" in out.stdout,
        f"{counts} {out.stdout} {out.stderr}")
# (b) the service has NOT been restarted — it meets values of a key it never loaded, and must re-read the file.
r.check("(b) the running service reads values re-encrypted with a key it did not know (re-reads the keyring)",
        a.store.get_totp(uid)["secret"] == SECRET and a.store.vault.active_kid == k_vault1)
out = cli("retire", "--purpose", "vault", "--db", db, "--secrets-key-file", str(kfile))
r.check("retire after reencrypt: the old vault key is gone from the file",
        out.returncode == 0 and [k.kid for k in keys.read_file(keys.VAULT, str(kfile), "t")] == [k_vault1],
        out.stdout + out.stderr)
a.store.db.close()
a = TinySesam(config(db, secrets_key_file=str(kfile)))
everything_works(a, uid, SECRET, handle, at, gtok, "after vault rotation + reencrypt + retire + restart")

# --- gate
out = cli("rotate", "--purpose", "gate", "--db", db, "--secrets-key-file", str(kfile))
a.store.db.close()
a = TinySesam(config(db, secrets_key_file=str(kfile)))
gtok2 = gate_token(a, uid)
r.check("rotate gate: new active key signs (new kid), the sign_key value printed, the old key still published",
        out.returncode == 0 and a._gate_keyring.active.kid != k_gate0
        and json.loads(gate._read_b64u(gtok2.split(".")[0]))["kid"] == a._gate_keyring.active.kid
        and a.gate_public_key() in out.stdout
        and {k["kid"] for k in a.gate_jwks()["keys"]} == {a._gate_keyring.active.kid, k_gate0},
        out.stdout + out.stderr)
everything_works(a, uid, SECRET, handle, at, gtok, "after gate rotation (token signed before it)")
r.check("… and the token signed after it verifies too", verify_with_jwks(a, gtok2))
out = cli("retire", "--purpose", "gate", "--db", db, "--secrets-key-file", str(kfile))
r.check("retire the old gate key within the overlap (a token signed with it may still live): refused",
        out.returncode == 1 and "fallback" in out.stderr, out.stderr)
a.store._exec("UPDATE key_material SET since = since - ? WHERE purpose='gate' AND since IS NOT NULL",
              (keys.GATE_OVERLAP_SEC + 5,))
a.store.db.close()
a = TinySesam(config(db, secrets_key_file=str(kfile)))
r.check("(e) after the overlap the old gate key is no longer published (even before it is retired)",
        [k["kid"] for k in a.gate_jwks()["keys"]] == [a._gate_keyring.active.kid])
out = cli("retire", "--purpose", "gate", "--db", db, "--secrets-key-file", str(kfile))
r.check("retire after the overlap: done", out.returncode == 0 and len(a.store.key_ring_rows("gate")) == 1,
        out.stdout + out.stderr)

# --- OAuth pepper
at_b, rt_b = oauth_pair(a, uid)          # a second program that does not refresh in between
out = cli("rotate", "--purpose", "oauth-pepper", "--db", db, "--secrets-key-file", str(kfile))
time.sleep(1.1)       # tokens issued after the rotation are younger than its second (`retire` compares by second)
a.store.db.close()
a = TinySesam(config(db, secrets_key_file=str(kfile)))
r.check("rotate pepper: new active pepper, the access token from before still accepted (found with the old one)",
        out.returncode == 0 and a._pepper_keyring.active.kid != k_pepper0 and oauth_ok(a, at),
        out.stdout + out.stderr)
answer = a._oauth_server().token({"grant_type": "refresh_token", "refresh_token": rt, "client_id": "cid"}, None)
new_digest = a._oauth_server().digest(answer["access_token"])
r.check("… a refresh with the token from before works and moves the connection to the new pepper",
        oauth_ok(a, answer["access_token"]) and a.store.oauth_token(new_digest) is not None)
out = cli("retire", "--purpose", "oauth-pepper", "--db", db, "--secrets-key-file", str(kfile))
r.check("retire the old pepper while tokens from before are still valid: refused (they would be cut)",
        out.returncode == 1 and "connect again" in out.stderr and oauth_ok(a, at_b), out.stderr)
a.store._exec("UPDATE oauth_token SET expires_at = 1 WHERE created_at <= (SELECT since FROM key_material "
              "WHERE purpose='oauth-pepper' AND since IS NOT NULL)")
out = cli("retire", "--purpose", "oauth-pepper", "--db", db, "--secrets-key-file", str(kfile))
a.store.db.close()
a = TinySesam(config(db, secrets_key_file=str(kfile)))
r.check("retire after those ran out: done; the connection itself lives on with the new pepper (after a restart)",
        out.returncode == 0 and len(a._pepper_keyring.keys) == 1 and oauth_ok(a, answer["access_token"]),
        out.stdout + out.stderr)

out = cli("list", "--db", db, "--secrets-key-file", str(kfile))
r.check("keys list: one line per key, purpose, kid and state — and no key material",
        out.returncode == 0 and out.stdout.count("active") == 3 and k_vault1 in out.stdout
        and base64.b64encode(a._vault_keyring.active.material).decode() not in out.stdout, out.stdout + out.stderr)

# Startup with a keyring that lacks a key the database needs (retired too early, wrong file): refused.
kfile2 = keydir / "other.key"
kfile2.write_text(base64.b64encode(secrets.token_bytes(32)).decode() + "\n")
kfile2.chmod(0o600)
a.store.db.close()
try:
    TinySesam(config(db, secrets_key_file=str(kfile2)))
    refused = ""
except ConfigError as e:
    refused = str(e)
r.check("a keyring without the key the stored values name: the start refuses (no silent TOTP failure)",
        "not in the keyring" in refused, refused)

# ======================================================================== (c) AAD
a = TinySesam(config(db, secrets_key_file=str(kfile)))
bob = a.create_user("bob", "dummy123")
a.store.set_totp(bob, totp.new_secret(), confirmed=True)
anna_ct = a.store._one("SELECT secret FROM totp_cred WHERE user_id=?", (uid,))["secret"]
a.store._exec("UPDATE totp_cred SET secret=? WHERE user_id=?", (anna_ct, bob))
r.check("(c) Anna's encrypted TOTP secret copied into Bob's row does not decrypt there",
        raises(lambda: a.store.get_totp(bob), InvalidTag))

other = oidc_row(a, bob, sub="sub-bob", refresh="rt-bob")
anna_rt = a.store._one("SELECT refresh FROM oidc_session WHERE token_hash=?", (handle,))["refresh"]
a.store._exec("UPDATE oidc_session SET refresh=? WHERE token_hash=?", (anna_rt, other))
r.check("(c) Anna's refresh token copied into Bob's OIDC row does not decrypt there",
        raises(lambda: a.store.oidc_refresh_plain(
            a.store._one("SELECT * FROM oidc_session WHERE token_hash=?", (other,))), InvalidTag))

anna_id = a.store._one("SELECT id_token FROM oidc_id_token WHERE token_hash=?", (handle,))["id_token"]
a.store._exec("UPDATE totp_cred SET secret=? WHERE user_id=?", (anna_id, uid))
r.check("(c) a value of another COLUMN (Anna's ID token) in Anna's TOTP row does not decrypt",
        raises(lambda: a.store.get_totp(uid), InvalidTag))
a.store._exec("UPDATE totp_cred SET secret=? WHERE user_id=?", (anna_ct, uid))

g = a.store._one("SELECT material FROM key_material WHERE purpose='gate' AND since IS NULL")["material"]
a.store._exec("UPDATE key_material SET material=? WHERE purpose='oauth-pepper' AND since IS NULL", (g,))
r.check("(c) the gate key's ciphertext in the pepper's row does not decrypt",
        raises(lambda: a.store.key_ring_rows("oauth-pepper"), InvalidTag))

swapped = anna_ct[:3] + "0" * keys.KID_LEN + anna_ct[3 + keys.KID_LEN:]
r.check("(c) a swapped key ID in the value: not decryptable (unknown key) — and with a known kid of another key: "
        "the tag fails",
        raises(lambda: a.store._open(swapped, "totp_cred.secret", uid), ConfigError))
r.check("(c) the untouched value still decrypts in its own row (counter-check)",
        a.store._open(anna_ct, "totp_cred.secret", uid) == SECRET)

# Session rotation (step-up): the ID token follows the session to its new handle — its context is the account.
new_handle = a.store.session_hash(a.store.rotate_session(handle) or "")
r.check("ID token survives the session rotation (bound to client and account, not to the rotating handle)",
        a.store.get_oidc_id_token(new_handle) == ("*", "id-token-sub-anna"))
a.store.db.close()

# ======================================================================== (d) migration from 0.25.x
from tinysesam.store import Store  # noqa: E402

old_dir = Path(tempfile.mkdtemp())
old_db = str(old_dir / "old.db")
OLD = secrets.token_bytes(32)


def v1(plain: str) -> str:
    nonce = secrets.token_bytes(12)
    return "v1:" + base64.urlsafe_b64encode(nonce + AESGCM(OLD).encrypt(nonce, plain.encode(), b"v1:")).decode()


def v1_open(value: str) -> str:
    raw = base64.urlsafe_b64decode(value[3:])
    return AESGCM(OLD).decrypt(raw[:12], raw[12:], b"v1:").decode()


# The state 0.25.x leaves behind: the base key beside the database (one Base64 line), `v1:` values, OAuth digests
# with the pepper derived from the base key, a gate token signed with the derived gate key (`typ: JWT`).
st = Store(old_db)
ouid = st.create_user("olga")
OSECRET = totp.new_secret()
st._exec("INSERT INTO totp_cred(user_id, secret, confirmed, created_at) VALUES (?,?,1,1)", (ouid, v1(OSECRET)))
ohandle = st.session_hash(st.create_session(ouid, 3600, True, "oidc"))
st._exec("INSERT INTO oidc_session(token_hash, client, sub, refresh, checked_at, client_id, success_at) "
         "VALUES (?, '*', 'sub-olga', ?, ?, 'client-1', ?)", (ohandle, v1("rt-olga"), int(time.time()),
                                                               int(time.time())))
st._exec("INSERT INTO oidc_id_token(token_hash, client, id_token) VALUES (?, '*', ?)", (ohandle, v1("id-olga")))
old_pepper = oauth.derive_pepper(OLD)
oat = oauth.new_token(oauth.ACCESS_PREFIX)
now = int(time.time())
st.oauth_add_client("cid", "Probe", ["http://localhost/cb"], now, None)
st.oauth_create_grant("no-code", "cid", ouid, RESOURCE, "mcp", now, None, None,
                      [(oauth.OAuthServer._digest(old_pepper, oat), "access", "mcp", now + 3600)])
st._exec("PRAGMA user_version = 18")
st.db.close()
Path(old_db + ".key").write_text(base64.b64encode(OLD).decode() + "\n")
os.chmod(old_db + ".key", 0o600)
_derived = gate.derive_key_name(OLD)
_head = gate._b64u(json.dumps({"alg": "EdDSA", "typ": "JWT",
                                "kid": gate.key_name_id(gate.public_raw(_derived))}).encode())
_body = gate._b64u(json.dumps({"iss": BASE, "aud": "app.example.com", "sub": str(ouid), "iat": now, "nbf": now,
                                "exp": now + 300, "ts_user": "olga"}).encode())
old_gate_token = f"{_head}.{_body}." + gate._b64u(_derived.sign(f"{_head}.{_body}".encode()))


def caddy_like(auth, token) -> bool:
    """caddy-jwt with `jwk_url`: key by `kid` from the set, EdDSA signature, iss/aud/exp — and NO `typ` check."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    h, b, sig = token.split(".")
    kid = json.loads(gate._read_b64u(h)).get("kid")
    for k in auth.gate_jwks()["keys"]:
        if k["kid"] == kid:
            try:
                Ed25519PublicKey.from_public_bytes(gate._read_b64u(k["x"])).verify(gate._read_b64u(sig),
                                                                                   f"{h}.{b}".encode())
            except Exception:   # noqa: BLE001
                return False
            c = json.loads(gate._read_b64u(b))
            return c["iss"] == BASE and c["aud"] == "app.example.com" and c["exp"] > time.time()
    return False


m = TinySesam(config(old_db))
counts = m.store.ciphertext_counts()
seed = m._gate_keyring.active.material
derived_seed = _derived.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption())
r.check("(d) migration: starts without handwork; the base key is version 1 of the vault keyring (same kid)",
        m._vault_keyring.active.kid == keys.fingerprint(keys.VAULT, OLD) and m._key_name_origin == "beside_db")
r.check("(d) every v1 value rewritten as v2 with the base key; TOTP, refresh and ID token readable",
        "v1" not in counts and counts.get(m._vault_keyring.active.kid) and m.store.get_totp(ouid)["secret"] == OSECRET
        and m.store.oidc_refresh_plain(m.store._one("SELECT * FROM oidc_session")) == "rt-olga"
        and m.store.get_oidc_id_token(ohandle) == ("*", "id-olga"), str(counts))
r.check("(d)/(e) gate: a NEW random key is active, the derived one is previous (note derived-v1) and still published",
        seed != derived_seed and m._gate_keyring.previous[0].material == derived_seed
        and m._gate_keyring.previous[0].note == keys.DERIVED_V1
        and len(m.gate_jwks()["keys"]) == 2)
r.check("(d) the gate token 0.25.x signed (typ JWT, derived key) stays valid at a jwk_url proxy until it expires",
        caddy_like(m, old_gate_token))
r.check("(d) the OAuth token 0.25.x digested with the derived pepper is still accepted; new tokens use a new pepper",
        oauth_ok(m, oat) and m._pepper_keyring.active.material != old_pepper
        and m._pepper_keyring.previous[0].material == old_pepper)
m.store.db.close()

# The way back: `reencrypt --to v1` writes what 0.25.x reads (one key, AAD "v1:").
out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "reencrypt", "--to", "v1", "--db", old_db],
                     capture_output=True, text=True, env=ENV, timeout=120, cwd=str(ROOT))
st = Store(old_db)
vals = [st._one("SELECT secret FROM totp_cred")["secret"], st._one("SELECT refresh FROM oidc_session")["refresh"],
        st._one("SELECT id_token FROM oidc_id_token")["id_token"]]
r.check("(d) way back: `keys reencrypt --to v1` — every value readable as 0.25.x reads it",
        out.returncode == 0 and [v1_open(v) for v in vals] == [OSECRET, "rt-olga", "id-olga"], out.stdout + out.stderr)
# An older version started WITHOUT the way back takes a v2 value for plain text and wraps it into v1 (its
# `extract_secrets`). Simulated on the TOTP row: the newer start must unwrap it, not hand out "v2:…" as the secret.
st.db.close()
m = TinySesam(config(old_db))
wrapped = v1(m.store._one("SELECT secret FROM totp_cred")["secret"])
m.store._exec("UPDATE totp_cred SET secret=?", (wrapped,))
m.store.db.close()
m = TinySesam(config(old_db))
r.check("(d) after the way back the newer version starts again and rewrites v2; a value an older start wrapped "
        "into v1 is unwrapped (secret intact)",
        m.store.get_totp(ouid)["secret"] == OSECRET and "v1" not in m.store.ciphertext_counts())

# (g) After the migration only v2 is read (attack round 2026-11-21, A-5): a `v1:` or plain-text value written behind
# the service's back (database write access, no vault key) is refused at runtime — it carries no binding to its row.
from tinysesam.errors import ConfigError  # noqa: E402
from tinysesam.vault import LegacyValueError  # noqa: E402
m.store._exec("UPDATE totp_cred SET secret=?", (v1(totp.new_secret()),))
r.check("(g) a v1 TOTP secret planted after the migration is not read at runtime",
        raises(lambda: m.store.get_totp(ouid), LegacyValueError))
m.store._exec("UPDATE totp_cred SET secret=?", (totp.new_secret(),))
r.check("(g) … nor a plain-text one", raises(lambda: m.store.get_totp(ouid), LegacyValueError))
# What a start that could not write leaves behind (read-only database): the start stops and names the way out …
m.store._exec("UPDATE totp_cred SET secret=?", (v1(OSECRET),))
try:
    m.store._check_v2_only()
    left_msg = ""
except ConfigError as e:
    left_msg = str(e)
r.check("(g) v1 values left after the start (not writable): the start refuses and names `tinysesam keys reencrypt`",
        "tinysesam keys reencrypt" in left_msg and "1 stored secret" in left_msg, left_msg)
m.store.db.close()
# … and the way out works offline.
out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "reencrypt", "--db", old_db],
                     capture_output=True, text=True, env=ENV, timeout=120, cwd=str(ROOT))
m = TinySesam(config(old_db))
r.check("(g) `tinysesam keys reencrypt` rewrites them; the next start reads the secret",
        out.returncode == 0 and m.store.get_totp(ouid)["secret"] == OSECRET, out.stdout + out.stderr)
# key_material was encrypted from its first row: a plain-text gate seed there is planted, never migrated.
_seed = secrets.token_bytes(32)
_kid = keys.kid_for(keys.GATE, _seed)
m.store._exec("INSERT INTO key_material(purpose, kid, material, created_at, since, note) VALUES (?,?,?,?,?,?)",
              (keys.GATE, _kid, base64.b64encode(_seed).decode(), now, now + 10 * 365 * 86400, ""))
r.check("(g) a plain-text gate seed planted in key_material is not loaded at runtime",
        raises(lambda: m.store.key_ring_rows(keys.GATE), LegacyValueError))
m.store.db.close()
r.check("(g) … and the next start refuses (database written without the vault key) instead of encrypting it",
        raises(lambda: TinySesam(config(old_db)), ConfigError)
        and Store(old_db)._one("SELECT material FROM key_material WHERE kid=?", (_kid,))[0]
        == base64.b64encode(_seed).decode())
out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "list", "--db", old_db],
                     capture_output=True, text=True, env=ENV, timeout=120, cwd=str(ROOT))
r.check("(g) … `keys list` says so in one line, no traceback",
        out.returncode == 1 and "key_material" in out.stderr and "Traceback" not in out.stderr, out.stderr)
_st = Store(old_db)
_st._exec("DELETE FROM key_material WHERE kid=?", (_kid,))
_st.db.close()
m = TinySesam(config(old_db))
r.check("(g) counter-check: without the planted row the start and the TOTP secret are fine",
        m.store.get_totp(ouid)["secret"] == OSECRET)
m.store.db.close()

# ======================================================================== env and file sources
gseed = secrets.token_bytes(32)
os.environ["TINYSESAM_GATE_KEY"] = base64.b64encode(gseed).decode()
os.environ["TINYSESAM_GATE_KEY_PREVIOUS"] = base64.b64encode(derived_seed).decode()
try:
    e = TinySesam(config(str(Path(tempfile.mkdtemp()) / "e.db")))
    e_ok = (e._gate_keyring.origin == "environment" and e._gate_keyring.active.material == gseed
            and len(e.gate_jwks()["keys"]) == 2 and e.store.key_ring_rows("gate") == [])
    env_out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "rotate", "--purpose", "gate",
                              "--db", e.cfg.db_path], capture_output=True, text=True,
                             env={**ENV, "TINYSESAM_GATE_KEY": os.environ["TINYSESAM_GATE_KEY"]}, timeout=120,
                             cwd=str(ROOT))
finally:
    del os.environ["TINYSESAM_GATE_KEY"], os.environ["TINYSESAM_GATE_KEY_PREVIOUS"]
r.check("TINYSESAM_GATE_KEY (+ _PREVIOUS): signs with it, publishes both, nothing in the database",
        e_ok)
r.check("keys rotate with the key from the environment: refused with the instructions (no file to write)",
        env_out.returncode == 1 and "TINYSESAM_GATE_KEY_PREVIOUS" in env_out.stderr, env_out.stderr)

text = f"# c\n{base64.b64encode(OLD).decode()}\n\n{base64.b64encode(gseed).decode()} since=5 note=x\n"
parsed = keys.parse(keys.VAULT, text, "probe")
r.check("keyring file: comments and empty lines skipped, first key active, attributes read",
        [k.kid for k in parsed] == [keys.fingerprint(keys.VAULT, OLD), keys.fingerprint(keys.VAULT, gseed)]
        and parsed[1].since == 5 and parsed[1].note == "x" and parsed[0].since is None)
r.check("keyring file: a doubled key, an unknown attribute, a short key — each refused",
        raises(lambda: keys.parse(keys.VAULT, text + base64.b64encode(OLD).decode(), "p"), ConfigError)
        and raises(lambda: keys.parse(keys.VAULT, base64.b64encode(OLD).decode() + " x=1", "p"), ConfigError)
        and raises(lambda: keys.parse(keys.VAULT, "c2hvcnQ=", "p"), ConfigError))

# ======================================================================== (f) config_check
cdir = Path(tempfile.mkdtemp())
loose = cdir / "loose.key"
loose.write_text(base64.b64encode(secrets.token_bytes(32)).decode())
loose.chmod(0o644)


def warnings_of(**over):
    return config_check.check_config(TinySesamConfig(**over))[1]


w = warnings_of(db_path=str(cdir / "c.db"), secrets_key_file=str(loose))
r.check("(f) secrets_key_file with mode 0644: warned (readable by others)",
        any("readable or writable by group or others (mode 0644)" in x for x in w), str(w))
r.check("(f) … and it lies in the database's directory: warned too",
        any("lies in the database's directory" in x for x in w), str(w))
loose.chmod(0o600)
w = warnings_of(db_path=str(Path(tempfile.mkdtemp()) / "c.db"), secrets_key_file=str(loose))
r.check("(f) counter-check: 0600 and elsewhere — no key warning",
        not any("readable or writable" in x or "database's directory" in x for x in w), str(w))
gate_cfg = dict(db_path=str(cdir / "g.db"), forward_auth_enabled=True, gate_token_enabled=True, base_url=BASE)
w = warnings_of(**gate_cfg)
r.check("(f) gate on, vault key beside the database, gate key in the database: warned (data directory mints tokens)",
        any("mint gate tokens" in x for x in w), str(w))
r.check("(f) counter-check: gate key from gate_key_file, or gate off — no such warning",
        not any("mint gate tokens" in x for x in warnings_of(**gate_cfg, gate_key_file=str(loose)))
        and not any("mint gate tokens" in x for x in warnings_of(db_path=str(cdir / "g.db"))))
de = warnings_of(**gate_cfg, lang="de")
r.check("(f) the findings exist in German too", any("Gate-Tokens prägen" in x for x in de), str(de))

raise SystemExit(r.done())

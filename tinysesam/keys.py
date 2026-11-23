"""The installation's keys: one purpose per key, each with a key ID and versions (T-48, ADR-12).

Up to 0.25.x ONE base key did everything: it encrypted the TOTP secrets and the OIDC tokens, and by HKDF it
WAS the gate signing key and the OAuth pepper. Whoever could read `<db>.key` could therefore mint a gate token
for any account, and there was no way to change it without losing every TOTP enrolment. Now:

| purpose        | protects                                     | material                    | where it comes from         |
|----------------|----------------------------------------------|-----------------------------|-----------------------------|
| `vault`        | reversible secrets at rest (AES-256-GCM)     | 32 random bytes             | `TINYSESAM_SECRETS_KEY`, `secrets_key_file`, else `<db>.key` |
| `gate`         | signature of the gate tokens (Ed25519)       | 32-byte seed, random        | `TINYSESAM_GATE_KEY`, `gate_key_file`, else the table `key_material` |
| `oauth-pepper` | HMAC of the stored OAuth token digests       | at least 32 random bytes    | `TINYSESAM_OAUTH_PEPPER`, `oauth_pepper_file`, else `key_material` |
| `approval`     | signature of the approval confirmations (Ed25519) | 32-byte seed, random   | `TINYSESAM_APPROVAL_KEY`, `approval_key_file`, else `key_material` |

The approval key signs only the one-time confirmations an application picks up after a person confirmed one of its
actions (`tinysesam.approval_token`). It is never the gate key: the proxy checks gate tokens by the key alone (it
cannot check `typ`), so a confirmation signed with the gate key could pass as a gate token, and a gate token as a
confirmation at an application with a weak check (RFC 8725 §3.11/§3.12).

The gate key and the pepper are their OWN random material, never derived from the vault key: reading the
vault key alone (a leaked environment, a key backup) no longer mints gate tokens. Without an own source they are
stored in the database, encrypted with the vault key (AAD-bound to purpose and key ID) — then it takes the
database AND the vault key; the default `<db>.key` beside the database gives both, which `config_check` says.

Every purpose is a **keyring**: the first key is active (encrypts, signs, digests), the others are "previous"
(decrypt, verify, look up) until they are retired. The pattern is the usual one — Django `SECRET_KEY_FALLBACKS`,
Rails `ActiveRecord::Encryption` with `previous:` keys, Tink keysets (one primary key, further enabled keys, the key
ID in every ciphertext). Rotation is `tinysesam keys rotate`, re-encryption `tinysesam keys reencrypt`, removal
`tinysesam keys retire` — the last one refuses while anything still needs the key.

Keyring file (`secrets_key_file`, `gate_key_file`, `oauth_pepper_file`, `<db>.key`), text, mode 0600::

    # comment lines and empty lines are ignored
    <Base64 of the active key>
    <Base64 of an older key> since=<unix time it stopped being active> [note=derived-v1]

A file with a single Base64 line — the format up to 0.25.x — is a keyring with one active key. The environment
variables hold the active key; `<NAME>_PREVIOUS` holds older ones, separated by spaces or commas.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .errors import ConfigError

VAULT = "vault"
GATE = "gate"
PEPPER = "oauth-pepper"
APPROVAL = "approval"
PURPOSES = (VAULT, GATE, PEPPER, APPROVAL)
#: The purposes whose key is an Ed25519 seed (sign, publish the public half as a JWKS).
SIGNING = (GATE, APPROVAL)

#: Environment variable with the active key per purpose; `<name>_PREVIOUS` holds older ones.
ENV = {VAULT: "TINYSESAM_SECRETS_KEY", GATE: "TINYSESAM_GATE_KEY", PEPPER: "TINYSESAM_OAUTH_PEPPER",
       APPROVAL: "TINYSESAM_APPROVAL_KEY"}
#: The configuration field with the keyring file per purpose.
FILE_FIELD = {VAULT: "secrets_key_file", GATE: "gate_key_file", PEPPER: "oauth_pepper_file",
              APPROVAL: "approval_key_file"}

#: How long a previous gate key stays published after it stopped signing: the longest a gate token can live
#: (`gate.TTL_MAX`). After that no token signed with it is valid any more, and the proxy may forget it.
GATE_OVERLAP_SEC = 3600
#: The same for the approval key: a confirmation is signed when the application picks it up and lives at most 300 s
#: (`approval_token.MAX_LIFETIME`); with the largest clock leeway of a checking application (30 s) and a margin,
#: nothing signed with a retired key is valid after this.
APPROVAL_OVERLAP_SEC = 600
#: The overlap per signing purpose.
OVERLAP_SEC = {GATE: GATE_OVERLAP_SEC, APPROVAL: APPROVAL_OVERLAP_SEC}

#: Note on a key that a migration took over from the time of the single base key (derived from it by HKDF).
DERIVED_V1 = "derived-v1"

log = logging.getLogger("tinysesam")


@dataclass(frozen=True)
class Key:
    kid: str
    material: bytes = field(repr=False)
    #: For a previous key: the Unix time at which it stopped being the active one — None if unknown (a key from
    #: the environment, or written without a date): then it counts as recent. Which key is active is its POSITION
    #: (the first), never this field.
    since: Optional[int] = None
    note: str = ""


@dataclass
class Keyring:
    purpose: str
    keys: list
    #: environment | file | beside_db | beside_db_new | database | memory | legacy
    origin: str
    #: The keyring file, if the keys come from one (`tinysesam keys rotate` writes it).
    path: str = ""

    @property
    def active(self) -> Key:
        return self.keys[0]

    @property
    def previous(self) -> list:
        return self.keys[1:]

    def find(self, kid: str) -> Optional[Key]:
        return next((k for k in self.keys if k.kid == kid), None)

    def kids(self) -> list:
        return [k.kid for k in self.keys]


# ---------- key IDs ----------

#: Length of a vault/pepper key ID in hex characters — fixed, the vault format relies on it (`v2:<kid>:`).
KID_LEN = 12


def fingerprint(purpose: str, material: bytes) -> str:
    """The key ID of a symmetric key: an HMAC with the key over its purpose — it names the key without revealing
    anything about it, and the same material always gets the same ID (also from the environment, without a file)."""
    return hmac.new(material, b"tinysesam/kid/" + purpose.encode("ascii"), hashlib.sha256).hexdigest()[:KID_LEN]


def gate_private(seed: bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(seed)


def kid_for(purpose: str, material: bytes) -> str:
    if purpose in SIGNING:
        from . import gate as _gate
        return _gate.key_name_id(_gate.public_raw(gate_private(material)))
    return fingerprint(purpose, material)


def new_material(purpose: str) -> bytes:
    return secrets.token_bytes(32)


# ---------- reading and writing ----------

def _material(purpose: str, text: str, origin: str) -> bytes:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (ValueError, TypeError):
        raise ConfigError(f"{origin}: not valid Base64.") from None
    if purpose == PEPPER:
        if len(raw) < 32:
            raise ConfigError(f"{origin}: the OAuth pepper must be at least 32 bytes (Base64 of 32 random bytes), "
                              f"it has {len(raw)}.")
    elif len(raw) != 32:
        raise ConfigError(f"{origin}: the key must be 32 bytes long (Base64 of 32 random bytes, e.g. "
                          f"`python -c \"import os,base64;print(base64.b64encode(os.urandom(32)).decode())\"`), "
                          f"it has {len(raw)}.")
    return raw


def parse(purpose: str, text: str, origin: str) -> list:
    """The keys of a keyring file's text — the first one active. Raises `ConfigError` on anything malformed."""
    keys: list = []
    seen: set = set()
    for number, line in enumerate(str(text).splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        value, *attributes = line.split()
        where = f"{origin}, line {number}"
        material = _material(purpose, value, where)
        since, note = None, ""
        for attribute in attributes:
            name, _, content = attribute.partition("=")
            if name == "since" and content.isdigit():
                since = int(content)
            elif name == "note" and content:
                note = content
            else:
                raise ConfigError(f"{where}: unknown attribute {name!r} (allowed: since=<unix time>, note=<word>).")
        kid = kid_for(purpose, material)
        if kid in seen:
            raise ConfigError(f"{where}: the same key twice (kid {kid}).")
        seen.add(kid)
        keys.append(Key(kid, material, None if not keys else since, note))
    if not keys:
        raise ConfigError(f"{origin}: no key in it.")
    return keys


def render(purpose: str, keys: list) -> str:
    lines = [f"# TinySesam keyring ({purpose}). The first key is active, the others only "
             f"{'verify' if purpose in SIGNING else 'decrypt' if purpose == VAULT else 'look up'}.",
             "# Edited by `tinysesam keys rotate|retire`. Secret: mode 0600, back it up apart from the database."]
    for i, k in enumerate(keys):
        line = base64.b64encode(k.material).decode("ascii")
        if i and k.since is not None:
            line += f" since={int(k.since)}"
        if k.note:
            line += f" note={k.note}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def read_file(purpose: str, path: str, origin_name: str) -> list:
    try:
        with open(path, encoding="ascii") as f:
            return parse(purpose, f.read(), f"{origin_name} {path!r}")
    except OSError as e:
        raise ConfigError(f"{origin_name} {path!r} cannot be read: {e}") from e
    except UnicodeDecodeError:
        raise ConfigError(f"{origin_name} {path!r}: not a text file.") from None


def write_file(purpose: str, path: str, keys: list) -> None:
    """Replace a keyring file atomically, with the owner and mode of the old one (at most 0600).

    A file written by root next to a service that runs as its own user would lock the service out of its key —
    so if the owner cannot be kept, nothing is replaced."""
    st = os.stat(path)
    between = f"{path}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    fd = os.open(between, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            if (st.st_uid, st.st_gid) != (os.getuid(), os.getgid()):
                try:
                    os.fchown(f.fileno(), st.st_uid, st.st_gid)
                except OSError as e:
                    raise ConfigError(f"{path!r} belongs to another user ({st.st_uid}:{st.st_gid}) and its owner "
                                      f"cannot be kept: {e}. Run the command as the service's user.") from e
            os.fchmod(f.fileno(), st.st_mode & 0o600)
            f.write(render(purpose, keys))
            f.flush()
            os.fsync(f.fileno())
        os.replace(between, path)
    finally:
        try:
            os.unlink(between)
        except FileNotFoundError:
            pass          # replaced: the temporary name is gone, as it should be


def _from_env(purpose: str) -> Optional[list]:
    name = ENV[purpose]
    value = os.environ.get(name, "")
    if not value.strip():
        return None
    keys = [Key(kid_for(purpose, m := _material(purpose, value, name)), m)]
    for part in os.environ.get(name + "_PREVIOUS", "").replace(",", " ").split():
        m = _material(purpose, part, name + "_PREVIOUS")
        kid = kid_for(purpose, m)
        if all(k.kid != kid for k in keys):
            keys.append(Key(kid, m))
    return keys


def from_override(purpose: str, key_file: str) -> Optional[Keyring]:
    """The keyring from the environment or the configured file — or None if neither is set."""
    keys = _from_env(purpose)
    if keys is not None:
        return Keyring(purpose, keys, "environment")
    if key_file:
        return Keyring(purpose, read_file(purpose, key_file, FILE_FIELD[purpose]), "file", key_file)
    return None


# ---------- the vault keyring ----------

def load_vault(db_path: str, key_file: str = "") -> Keyring:
    """The vault keyring: environment, then `secrets_key_file`, then `<db>.key` (created on the first start)."""
    ring = from_override(VAULT, key_file)
    if ring is not None:
        return ring
    if not db_path or db_path == ":memory:":
        # An in-memory database lives as long as the process — so does its key.
        m = secrets.token_bytes(32)
        return Keyring(VAULT, [Key(fingerprint(VAULT, m), m)], "memory")
    path = db_path + ".key"
    try:
        return Keyring(VAULT, read_file(VAULT, path, "key file"), "beside_db", path)
    except ConfigError as e:
        if not isinstance(e.__cause__, FileNotFoundError):
            raise
    # Create atomically and exclusively: first a complete temporary file (0600, fsync), then a
    # hard link to the target name — that succeeds for exactly one process. Several workers starting
    # for the first time at once would otherwise read a half-written file or fail on
    # O_EXCL (attack on the second round, finding 10: 85 of 240 starts). The loser reads the
    # winner's file.
    raw = secrets.token_bytes(32)
    between = f"{path}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    fd = os.open(between, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(base64.b64encode(raw).decode("ascii") + "\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(between, path)
        except FileExistsError:
            return Keyring(VAULT, read_file(VAULT, path, "key file"), "beside_db", path)
    finally:
        # The temporary file has served its purpose (linked or lost) — get rid of it; the link
        # leaves it standing, so in the normal case it is still there.
        try:
            os.unlink(between)
        except FileNotFoundError:
            pass          # a foreign cleaner was faster — the goal was only that it does not remain
    log.warning(
        "TinySesam: key for the secrets at rest newly generated: %s (0600). It sits next to the "
        "database — that protects against a database file that leaks on its own, not against a "
        "backup of the whole directory. Store it separately: %s or secrets_key_file. And: "
        "without this key all TOTP enrollments are lost — back it up too, separately from the "
        "database.", path, ENV[VAULT])
    return Keyring(VAULT, [Key(fingerprint(VAULT, raw), raw)], "beside_db_new", path)


def reloader(db_path: str, key_file: str) -> Callable[[], Optional[Keyring]]:
    """Re-read the vault keyring from where it came from — for a running service that meets a ciphertext of a key it
    does not know yet (`keys rotate` + `keys reencrypt` before its restart). At most once per second; never creates a
    file, and from the environment there is nothing new to read."""
    lock = threading.Lock()
    last = [0.0]

    def again() -> Optional[Keyring]:
        with lock:
            if time.monotonic() - last[0] < 1.0:
                return None
            last[0] = time.monotonic()
        if _from_env(VAULT) is not None:
            return None
        path = key_file or ("" if not db_path or db_path == ":memory:" else db_path + ".key")
        if not path or not os.path.exists(path):
            return None
        try:
            return Keyring(VAULT, read_file(VAULT, path, FILE_FIELD[VAULT] if key_file else "key file"),
                           "file" if key_file else "beside_db", path)
        except ConfigError as e:
            log.error("TinySesam: re-reading the key file failed: %s", e)
            return None
    return again


# ---------- the keyrings in the database (gate, pepper, approval) ----------

def load_stored(purpose: str, store, key_file: str = "", legacy: Optional[bytes] = None) -> Keyring:
    """The keyring of `purpose` from the environment, its file or the database — created on the first start.

    `legacy`: the material that the version before derived from the base key. On the FIRST start it is kept as a
    previous key (note `derived-v1`), so that what it signed or digested stays valid until its natural end; the
    new active key is random. Read-only database without a keyring: the legacy material itself, loudly."""
    ring = from_override(purpose, key_file)
    if ring is not None:
        return ring
    try:
        rows = store.key_ring_rows(purpose)
        if not rows:
            store.key_ring_create(purpose, new_material(purpose), legacy)
            rows = store.key_ring_rows(purpose)
    except Exception as e:   # noqa: BLE001 — sqlite3.OperationalError (read-only) and the like
        if legacy is None or not _read_only(e):
            raise
        log.warning("TinySesam: the database is not writable — the %s key could not be created and stays the one "
                    "derived from the base key until a start with write access.", purpose)
        return Keyring(purpose, [Key(kid_for(purpose, legacy), legacy, None, DERIVED_V1)], "legacy")
    return Keyring(purpose, rows, "database")


def _read_only(e: Exception) -> bool:
    return "readonly" in str(e).replace("-", "").replace(" ", "").lower()


def jwks(ring: Keyring, now: int) -> dict:
    """The public keys of a signing keyring (gate or approval) as a JSON Web Key Set (RFC 7517, OKP/Ed25519 per
    RFC 8037): the active key and every previous one within the purpose's overlap (`OVERLAP_SEC`) of its retirement.
    The gate set is for caddy-jwt's `jwk_url`, the approval set for the applications that check confirmations."""
    from . import gate as _gate
    overlap = OVERLAP_SEC.get(ring.purpose, GATE_OVERLAP_SEC)
    out = []
    for i, k in enumerate(ring.keys):
        if i and k.since is not None and now - int(k.since) > overlap:
            continue
        pub = _gate.public_raw(gate_private(k.material))
        out.append({"kty": "OKP", "crv": "Ed25519", "x": _gate._b64u(pub), "kid": k.kid, "alg": "EdDSA",
                    "use": "sig"})
    return {"keys": out}

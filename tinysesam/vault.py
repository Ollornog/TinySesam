"""Encrypt reversible secrets at rest (H-14/H-15, PO decision 2026-09-24: mandatory; T-48/T-54: keyring and AAD).

Passwords, PINs, recovery codes, API keys and scope secrets are stored only as a hash. What has to come back as it
was — TOTP secrets, the refresh and ID tokens of OIDC sessions, an OAuth successor pair in its grace window, and the
gate key and OAuth pepper kept in the database — is AES-256-GCM-encrypted. Up to 0.20.x the TOTP secret was stored in
plain text: whoever had a copy of the file could generate valid codes for every account.

The key is NOT in the database. It is the `vault` keyring of `keys.py`: `TINYSESAM_SECRETS_KEY` (+ `_PREVIOUS`),
`secrets_key_file`, otherwise a file next to the database (`<db>.key`, 0600), created on first start — loudly, because
that protects against a database file that leaks ALONE, not against a backup of the whole directory.

**Without the key the TOTP setups are lost** — it belongs in the backup, separate from the database. If it does not
match the stored secrets, TinySesam does not start (`ConfigError`) instead of silently letting every TOTP sign-in fail.

Format of a value since 0.26 (T-48, T-54)::

    v2:<kid>:<Base64url(nonce 12 bytes ‖ ciphertext ‖ tag)>

`kid` names the key of the keyring that encrypted it (12 hex characters), so a rotated keyring decrypts old values
with their own key. The associated data (AAD) binds the value to its place: `kid` plus a context — table, column and
the row's identity (account, client, subject …, `Store._seal`). A value copied into another row or column, or one
whose `kid` was swapped, no longer decrypts (`InvalidTag`).

Nothing else is read (attack round 2026-11-21, A-5): `v1:` (one key, no context, up to 0.25.x) and plain text (before
0.21) were rewritten by the releases up to 0.30.0; since the schema baseline (T-111) a start that finds one stops and
names the way out (`Store._check_v2_only`).
"""
from __future__ import annotations

import base64
import json
import logging
import secrets
from typing import Callable, Optional

from .errors import ConfigError
from . import keys as _keys

PREFIX_V2 = "v2:"
ENV_VAR = _keys.ENV[_keys.VAULT]
log = logging.getLogger("tinysesam")


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:   # pragma: no cover — cryptography is a mandatory dependency
        raise ConfigError("The package `cryptography` is missing — it has been required since 0.21.0 "
                          "(TOTP secrets are encrypted).") from e
    return AESGCM


def context(column: str, *parts) -> str:
    """The context of a value: `table.column` and the identity of its row — unambiguous for any part (JSON)."""
    return json.dumps([column, *[str(p) for p in parts]], ensure_ascii=True, separators=(",", ":"))


def kid_of(value) -> Optional[str]:
    """The key ID of a `v2:` value, None for anything else."""
    v = str(value or "")
    if not v.startswith(PREFIX_V2) or v[3 + _keys.KID_LEN:4 + _keys.KID_LEN] != ":":
        return None
    return v[3:3 + _keys.KID_LEN]


class LegacyValueError(ValueError):
    """A stored secret is not in the format `v2:` (plain text, `v1:`, or planted) — see `Vault.decrypt`."""


class Vault:
    """Encrypt with the active key of the keyring, decrypt with whichever key a value names."""

    def __init__(self, keyring, reload: Optional[Callable[[], Optional[_keys.Keyring]]] = None):
        if isinstance(keyring, (bytes, bytearray)):
            keyring = _keys.Keyring(_keys.VAULT, [_keys.Key(_keys.fingerprint(_keys.VAULT, bytes(keyring)),
                                                            bytes(keyring))], "memory")
        self._reload = reload
        self._use(keyring)

    def _use(self, keyring) -> None:
        aead = _aesgcm()
        self.keyring = keyring
        self._aeads = {k.kid: aead(k.material) for k in keyring.keys}

    @property
    def active_kid(self) -> str:
        return self.keyring.active.kid

    @staticmethod
    def _aad(kid: str, ctx: str) -> bytes:
        return b"tinysesam/vault/v2\x00" + kid.encode("ascii") + b"\x00" + ctx.encode("utf-8")

    def encrypt(self, plaintext: str, ctx: str) -> str:
        kid = self.active_kid
        nonce = secrets.token_bytes(12)
        ciphertext = self._aeads[kid].encrypt(nonce, plaintext.encode("utf-8"), self._aad(kid, ctx))
        return f"{PREFIX_V2}{kid}:" + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def _key(self, kid: str):
        aead = self._aeads.get(kid)
        if aead is None and self._reload is not None:
            fresh = self._reload()
            if fresh is not None and fresh.find(kid) is not None:
                log.info("TinySesam: vault keyring re-read — key %s is new (rotated while running); "
                         "it is now the one that encrypts if it is the first.", kid)
                self._use(fresh)
                aead = self._aeads.get(kid)
        if aead is None:
            raise ConfigError(f"The key {kid} of a stored secret is not in the vault keyring (retired too early, or "
                              f"the wrong {ENV_VAR}/secrets_key_file).")
        return aead

    def decrypt(self, value: Optional[str], ctx: str) -> Optional[str]:
        """`None` stays `None`; a `v2:` value comes back decrypted. A wrong key, a wrong context or an altered value
        raises `cryptography.exceptions.InvalidTag`.

        Everything else raises `LegacyValueError`. Up to the attack round of 2026-11-21 (A-5) every read accepted plain
        text and `v1:`: whoever could write the database without the vault key planted a plain-text gate seed in
        `key_material` and had it published as a gate key, or a `v1:`/plain TOTP secret that the binding to its row
        (AAD) never saw."""
        if value is None:
            return None
        v = str(value)
        if v.startswith(PREFIX_V2):
            kid = kid_of(v)
            if kid is None:
                raise ValueError("malformed v2 value")
            raw = base64.urlsafe_b64decode(v[4 + _keys.KID_LEN:].encode("ascii"))
            return self._key(kid).decrypt(raw[:12], raw[12:], self._aad(kid, ctx)).decode("utf-8")
        raise LegacyValueError("a stored secret is not in the current format (v2) — a value of a version before "
                               "0.26 (TinySesam 0.30.0 re-encrypts it), or one that was planted")

    def needs_rewrite(self, value: Optional[str]) -> bool:
        """Is this stored value not (yet) in the current format with the active key?"""
        return value is not None and kid_of(value) != self.active_kid

    @staticmethod
    def is_encrypted(value: Optional[str]) -> bool:
        return bool(value) and str(value).startswith(PREFIX_V2)

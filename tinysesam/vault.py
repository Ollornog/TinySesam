"""Encrypt reversible secrets at rest (H-14/H-15, PO decision 2026-09-24: mandatory).

The only reversible secret in the database is the TOTP secret — passwords, PINs,
recovery codes, API keys and scope secrets are stored there only as a hash. Up to 0.20.x it was stored in
plain text: whoever had a copy of the file (a backup, a dump of the volume) could generate valid
codes for every account, so the second factor was only as strong as the safekeeping of the backups.

Now: AES-256-GCM, the key is NOT in the database. Where it comes from, in this order:

1. Environment variable `TINYSESAM_SECRETS_KEY` (32 bytes, Base64) — the way for container secrets.
2. `secrets_key_file` in the configuration (file with the same content).
3. Otherwise a key file next to the database (`<db>.key`, 0600), created on first start.
   Loudly: it protects against a database file that leaks ALONE, not against a backup
   of the whole directory. For real separation put the key elsewhere via 1. or 2.

**Without the key the TOTP setups are lost** — it belongs in the backup, separate
from the database. If it does not match the stored secrets, TinySesam does not start
(`ConfigError`) instead of silently letting every TOTP sign-in fail.

Format of a value: `v1:` + Base64url(nonce 12 bytes ‖ ciphertext ‖ tag). A value without prefix is
plain text from the time before and is encrypted at startup (`Store.geheimnisse_heben`).
"""
from __future__ import annotations

import base64
import logging
import os
import secrets
from typing import Optional

from .errors import ConfigError

PREFIX = "v1:"
ENV_VAR = "TINYSESAM_SECRETS_KEY"
log = logging.getLogger("tinysesam")


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:   # pragma: no cover — cryptography is a mandatory dependency
        raise ConfigError("Das Paket `cryptography` fehlt — es ist seit 0.21.0 Pflicht "
                          "(TOTP-Geheimnisse werden verschlüsselt).") from e
    return AESGCM


def _read_key(text: str, herkunft: str) -> bytes:
    try:
        roh = base64.b64decode(text.strip(), validate=True)
    except (ValueError, TypeError):
        raise ConfigError(f"{herkunft}: kein gültiges Base64.") from None
    if len(roh) != 32:
        raise ConfigError(f"{herkunft}: der Schlüssel muss 32 Byte lang sein (Base64 von 32 "
                          f"Zufallsbytes, z. B. `python -c \"import os,base64;"
                          f"print(base64.b64encode(os.urandom(32)).decode())\"`), er hat {len(roh)}.")
    return roh


def load_key(db_path: str, key_file: str = "") -> tuple[bytes, str]:
    """Find the key or create it (next to the database). Returns `(key, origin)`."""
    wert = os.environ.get(ENV_VAR, "")
    if wert.strip():
        return _read_key(wert, ENV_VAR), "umgebung"
    if key_file:
        try:
            with open(key_file, encoding="ascii") as f:
                return _read_key(f.read(), f"secrets_key_file {key_file!r}"), "datei"
        except OSError as e:
            raise ConfigError(f"secrets_key_file {key_file!r} lässt sich nicht lesen: {e}") from e
    if not db_path or db_path == ":memory:":
        # An in-memory database lives as long as the process — so does its key.
        return secrets.token_bytes(32), "speicher"
    pfad = db_path + ".key"
    try:
        with open(pfad, encoding="ascii") as f:
            return _read_key(f.read(), f"Schlüsseldatei {pfad!r}"), "neben_db"
    except FileNotFoundError:
        pass              # first start: there is none yet — it is created right away
    # Create atomically and exclusively: first a complete temporary file (0600, fsync), then a
    # hard link to the target name — that succeeds for exactly one process. Several workers starting
    # for the first time at once would otherwise read a half-written file or fail on
    # O_EXCL (attack on the second round, finding 10: 85 of 240 starts). The loser reads the
    # winner's file.
    roh = secrets.token_bytes(32)
    zwischen = f"{pfad}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    fd = os.open(zwischen, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(base64.b64encode(roh).decode("ascii") + "\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(zwischen, pfad)
        except FileExistsError:
            with open(pfad, encoding="ascii") as f:
                return _read_key(f.read(), f"Schlüsseldatei {pfad!r}"), "neben_db"
    finally:
        # The temporary file has served its purpose (linked or lost) — get rid of it; the link
        # leaves it standing, so in the normal case it is still there.
        try:
            os.unlink(zwischen)
        except FileNotFoundError:
            pass          # a foreign cleaner was faster — the goal was only that it does not remain
    log.warning(
        "TinySesam: Schlüssel für die TOTP-Geheimnisse neu erzeugt: %s (0600). Er liegt neben der "
        "Datenbank — das schützt gegen eine Datenbankdatei, die allein abfliesst, nicht gegen eine "
        "Sicherung des ganzen Verzeichnisses. Getrennt ablegen: %s oder secrets_key_file. Und: "
        "Ohne diesen Schlüssel sind alle TOTP-Einrichtungen verloren — mitsichern, getrennt von der "
        "Datenbank.", pfad, ENV_VAR)
    return roh, "neben_db_neu"


class Vault:
    """Encrypt and decrypt with ONE key (AES-256-GCM)."""

    def __init__(self, schluessel: bytes):
        self._aead = _aesgcm()(schluessel)

    def encrypt(self, klartext: str) -> str:
        nonce = secrets.token_bytes(12)
        chiffrat = self._aead.encrypt(nonce, klartext.encode("utf-8"), PREFIX.encode("ascii"))
        return PREFIX + base64.urlsafe_b64encode(nonce + chiffrat).decode("ascii")

    def decrypt(self, wert: Optional[str]) -> Optional[str]:
        """`None` stays `None`; a value without prefix is plain text from the time before
        encryption and comes back unchanged (until `geheimnisse_heben` encrypts it).
        A wrong key raises `cryptography.exceptions.InvalidTag`."""
        if wert is None or not str(wert).startswith(PREFIX):
            return wert
        roh = base64.urlsafe_b64decode(str(wert)[len(PREFIX):].encode("ascii"))
        return self._aead.decrypt(roh[:12], roh[12:], PREFIX.encode("ascii")).decode("utf-8")

    @staticmethod
    def is_encrypted(wert: Optional[str]) -> bool:
        return bool(wert) and str(wert).startswith(PREFIX)

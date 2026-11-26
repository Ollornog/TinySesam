"""The store part `factors`: sign-in factors: password, PIN, TOTP, recovery codes, passkeys.

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .keys import KID_LEN as _KID_LEN
from .store import (
    json,
)
import sqlite3
from typing import Optional


# ---------- Password ----------
def set_password_hash(self, user_id, hash_):
    self._exec("INSERT INTO password_cred(user_id, hash, updated_at) VALUES (?,?,?) "
               "ON CONFLICT(user_id) DO UPDATE SET hash=excluded.hash, updated_at=excluded.updated_at",
               (user_id, hash_, _store._now()))


def get_password_hash(self, user_id) -> Optional[str]:
    r = self._one("SELECT hash FROM password_cred WHERE user_id=?", (user_id,))
    return r["hash"] if r else None


# ---------- PIN ----------
def set_pin_hash(self, user_id, hash_):
    self._exec("INSERT INTO pin_cred(user_id, hash, updated_at) VALUES (?,?,?) "
               "ON CONFLICT(user_id) DO UPDATE SET hash=excluded.hash, updated_at=excluded.updated_at",
               (user_id, hash_, _store._now()))


def get_pin_hash(self, user_id) -> Optional[str]:
    r = self._one("SELECT hash FROM pin_cred WHERE user_id=?", (user_id,))
    return r["hash"] if r else None


def delete_pin(self, user_id):
    self._exec("DELETE FROM pin_cred WHERE user_id=?", (user_id,))


def has_pin(self, user_id) -> bool:
    return self.get_pin_hash(user_id) is not None


def set_totp(self, user_id, secret, confirmed=False):
    # `last_step` belongs to the secret: a new one starts without a consumed step. Otherwise
    # the confirmation code of a discarded attempt would lock the first code of the new one
    # if both fall into the same 30-second window.
    if self.vault is None:
        raise RuntimeError("TOTP secrets are only stored encrypted — the store has "
                           "no key (vault.Vault).")
    self._exec("INSERT INTO totp_cred(user_id, secret, confirmed, created_at) VALUES (?,?,?,?) "
               "ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, "
               "confirmed=excluded.confirmed, last_step=NULL",
               (user_id, self._seal(secret, "totp_cred.secret", user_id), 1 if confirmed else 0, _store._now()))


def confirm_totp(self, user_id):
    self._exec("UPDATE totp_cred SET confirmed=1 WHERE user_id=?", (user_id,))


def get_totp(self, user_id) -> Optional[dict]:
    """The TOTP row of an account, with the secret decrypted (`secret`)."""
    line = self._one("SELECT * FROM totp_cred WHERE user_id=?", (user_id,))
    if line is None:
        return None
    d = dict(line)
    if self.vault is not None:
        d["secret"] = self._open(d["secret"], "totp_cred.secret", user_id)
    return d


def extract_secrets(self) -> None:
    """At startup: check that the vault keyring fits the stored secrets and that every one is in the format `v2`.

    A key that does not fit is a `ConfigError`: a start with the wrong key would otherwise let every TOTP
    sign-in fail silently. So is a value in a format before 0.26 (`_check_v2_only`)."""
    from .errors import ConfigError
    if self.vault is None:
        return
    # Every key a stored value names must be in the keyring. All encrypted columns: if there are only refresh
    # tokens (OIDC instance without TOTP), a wrong key would otherwise start — and every request with an old
    # cookie ended in a 500.
    wrong = ("The key does not match the stored secrets (TOTP, OIDC tokens, the gate key or OAuth pepper kept "
             "in the database; wrong TINYSESAM_SECRETS_KEY/secrets_key_file, or the key file next to the "
             "database is missing or a different one). Use the right key — without it all accounts have to set "
             "up TOTP again (docs/OPERATIONS.md \"Keys\": key lost).")
    for spec in self.ENCRYPTED:
        table, column = spec[0].split(".")
        for (kid,) in self._all(f"SELECT DISTINCT substr({column}, 4, {_KID_LEN}) FROM {table} "
                                f"WHERE {column} LIKE 'v2:%'"):
            if self.vault.keyring.find(kid) is None:
                raise ConfigError(f"{wrong} (Key {kid} is not in the keyring — retired too early?)")
    self._check_v2_only()


def old_format_count(self) -> int:
    """Stored secrets outside `key_material` that are not in the format `v2` — `v1:` or plain text, written by a
    version before 0.26 and never re-encrypted. This version reads none of them (`_check_v2_only`)."""
    left = 0
    for column, _select in self.ENCRYPTED:
        if column == "key_material.material":
            continue
        table, col = column.split(".")
        left += self._one(f"SELECT COUNT(*) AS n FROM {table} WHERE {col} IS NOT NULL "
                          f"AND {col} NOT LIKE 'v2:%'")["n"]
    return int(left)


def _check_v2_only(self) -> None:
    """Every encrypted column holds `v2:` only — the runtime reads nothing else (A-5).

    `key_material` was encrypted from its first row: anything else there was planted or damaged, and is never
    "migrated" (encrypting it now would turn a planted gate seed into a real one). Elsewhere a `v1:` or plain value
    comes from a version before 0.26 that 0.30.0 never re-encrypted (a read-only start, `keys reencrypt` not run):
    this version cannot rewrite it, so the start stops and names the way out instead of failing every TOTP
    sign-in with a 500."""
    from .errors import ConfigError
    planted = self._one("SELECT COUNT(*) AS n FROM key_material WHERE material IS NULL "
                        "OR material NOT LIKE 'v2:%'")["n"]
    if planted:
        raise ConfigError(f"key_material holds {planted} value(s) that are not vault ciphertext. TinySesam has "
                          "only ever written that table encrypted, so the database was written without the vault "
                          "key or is damaged — restore it from a backup (docs/OPERATIONS.md \"Keys\"). The rows "
                          "are not used.")
    left = self.old_format_count()
    if left:
        raise ConfigError(f"{left} stored secret(s) are still in a format before 0.26 (v1: or plain text). This "
                          "version reads the format v2 only and no longer rewrites older ones. Re-encrypt them "
                          f"with TinySesam {self.LAST_MIGRATING_RELEASE}: start it once with write access, or run "
                          "its `tinysesam keys reencrypt --db <path>`; then start this version "
                          "(docs/OPERATIONS.md \"Updating\").")


def delete_totp(self, user_id):
    self._exec("DELETE FROM totp_cred WHERE user_id=?", (user_id,))


def has_confirmed_totp(self, user_id) -> bool:
    r = self.get_totp(user_id)
    return bool(r and r["confirmed"])


# ---------- Recovery codes ----------
def delete_recovery_codes(self, user_id):
    self._exec("DELETE FROM recovery_code WHERE user_id=?", (user_id,))


def add_recovery_codes(self, user_id, hashes):
    now = _store._now()
    with self._writing():
        self.db.executemany("INSERT INTO recovery_code(user_id, code_hash, created_at) VALUES (?,?,?)",
                            [(user_id, h, now) for h in hashes])
        self.db.commit()


def consume_recovery_code(self, user_id, code_hash) -> bool:
    """Invalidate an unused code atomically. True only on the first valid redemption."""
    with self._writing():
        cur = self.db.execute(
            "UPDATE recovery_code SET used_at=? WHERE id=(SELECT id FROM recovery_code "
            "WHERE user_id=? AND code_hash=? AND used_at IS NULL LIMIT 1)",
            (_store._now(), user_id, code_hash))
        self.db.commit()
        return cur.rowcount == 1


def count_recovery_codes(self, user_id) -> int:
    return self._one("SELECT COUNT(*) c FROM recovery_code WHERE user_id=? AND used_at IS NULL",
                     (user_id,))["c"]


# ---------- WebAuthn ----------
def add_webauthn(self, user_id, credential_id, public_key, sign_count, transports, name):
    self._exec("INSERT INTO webauthn_cred(user_id, credential_id, public_key, sign_count, transports, name, created_at) "
               "VALUES (?,?,?,?,?,?,?)",
               (user_id, credential_id, public_key, sign_count, json.dumps(transports or []), name, _store._now()))


def get_webauthn_by_credid(self, credential_id) -> Optional[sqlite3.Row]:
    return self._one("SELECT * FROM webauthn_cred WHERE credential_id=?", (credential_id,))


def list_webauthn(self, user_id):
    return self._all("SELECT * FROM webauthn_cred WHERE user_id=? ORDER BY created_at", (user_id,))


def update_webauthn_signcount(self, cred_row_id, sign_count):
    self._exec("UPDATE webauthn_cred SET sign_count=?, last_used=? WHERE id=?", (sign_count, _store._now(), cred_row_id))


def delete_webauthn(self, cred_row_id, user_id):
    self._exec("DELETE FROM webauthn_cred WHERE id=? AND user_id=?", (cred_row_id, user_id))


def recovery_codes_before(self, when: int) -> int:
    """Unused recovery codes made up to `when` — their digest carries a pepper retired at `when`. A code is not
    moved to the active pepper (only its digest is stored, and it is used once), so it needs the old pepper until
    it is used or the account generates new ones."""
    return int(self._one("SELECT COUNT(*) AS n FROM recovery_code WHERE created_at <= ? AND used_at IS NULL",
                         (when,))["n"])


def consume_totp_step(self, user_id, step: int) -> bool:
    """Book a TOTP time step as consumed. True if it was still free.

    The comparison and the write sit in ONE `UPDATE … WHERE`: two simultaneous
    requests with the same code cannot both win this way — SQLite serialises the
    writers, and the second hits no row any more.
    """
    cur = self._exec(
        "UPDATE totp_cred SET last_step=? WHERE user_id=? AND (last_step IS NULL OR last_step < ?)",
        (int(step), user_id, int(step)))
    return cur.rowcount == 1

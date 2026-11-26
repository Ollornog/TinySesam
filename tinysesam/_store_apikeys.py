"""The store part `apikeys`: API keys and app passwords (T-66).

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .store import (
    json,
)
import sqlite3
from typing import Optional


def get_api_key(self, key_id):
    """One API key row by its id (never the secret — only its digest is stored) — or None."""
    try:
        return self._one("SELECT * FROM api_key WHERE id=?", (int(key_id),))
    except (TypeError, ValueError, OverflowError):
        return None


# ---------- API keys ----------
def add_api_key(self, user_id, name, prefix, key_hash, roles=None, expires_at=None,
                kind: str = "automation") -> int:
    cur = self._exec(
        "INSERT INTO api_key(user_id, name, prefix, key_hash, roles, kind, created_at, expires_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (user_id, name, prefix, key_hash, json.dumps(list(roles or [])), kind, _store._now(), expires_at))
    return cur.lastrowid


def get_api_key_by_hash(self, key_hash):
    return self._one("SELECT * FROM api_key WHERE key_hash=?", (key_hash,))


def list_api_keys(self, user_id):
    return self._all("SELECT * FROM api_key WHERE user_id=? ORDER BY created_at DESC", (user_id,))


def touch_api_key(self, key_id):
    self._exec("UPDATE api_key SET last_used=? WHERE id=?", (_store._now(), key_id))


def source_mail_since(self, user_id, since) -> bool:
    """Has a confirmation request for an address from LDAP/SAML on this account been settled
    since `seit` (Unix seconds)? Delivered (G12a: the row `federation_email_confirm`, which arises only AFTER
    the successful send) or rejected because the address is taken or
    reserved (`email_change_taken`/`_reserved` from this path, attack round 2026-09-26 —
    otherwise every worker wrote its own row, and the account page counted along). Recognised by the
    detail that begins with `account=<id> `; self-service
    does not write it. Via
    `idx_audit_ts`, in the database and thus across all workers and every restart.
    The id instead of the name: a rename does not reset the daily quota."""
    return bool(self._one(
        "SELECT 1 FROM audit WHERE ts >= ? AND event IN (?, ?, ?) AND detail LIKE ? LIMIT 1",
        (int(since), *self.SOURCE_MAIL_DONE, f"account={int(user_id)} %")))


def open_token(self, user_id, purpose, email=None) -> bool:
    """Is there already an open (unused, valid) link of this purpose for this account —
    to this address, or without `email` to any? So that not every sign-in sends a new
    confirmation link. The LDAP/SAML path asks without an address (p2 F2): with the
    filter on the address a second worker sent a link to a different one as long as the
    first was still in the outbox — and from whether it arrived, a user who maintains their own `mail`
    could read whether the first address is taken."""
    if email is None:
        return bool(self._one("SELECT 1 FROM magic_token WHERE user_id=? AND purpose=? "
                              "AND used_at IS NULL AND expires_at >= ? LIMIT 1",
                              (user_id, purpose, _store._now())))
    return bool(self._one("SELECT 1 FROM magic_token WHERE user_id=? AND purpose=? AND email=? "
                          "AND used_at IS NULL AND expires_at >= ? LIMIT 1",
                          (user_id, purpose, email, _store._now())))


def revoke_user_api_keys(self, user_id) -> int:
    """Invalidate all still valid keys of an account. Returns how many there were —
    the number belongs in the log and in the response, otherwise nobody notices what silently
    dropped out (or keeps running)."""
    return self._exec("UPDATE api_key SET revoked=1 WHERE user_id=? AND revoked=0",
                      (user_id,)).rowcount


def count_active_api_keys(self, user_id) -> int:
    r = self._one("SELECT COUNT(*) AS n FROM api_key WHERE user_id=? AND revoked=0", (user_id,))
    return r["n"] if r else 0


def api_key_owner(self, key_id) -> Optional[int]:
    """The account ID for a key — for the audit row on revocation (B5-04)."""
    r = self._one("SELECT user_id FROM api_key WHERE id=?", (key_id,))
    return r["user_id"] if r else None


def revoke_api_key(self, key_id, user_id=None):
    if user_id is not None:
        self._exec("UPDATE api_key SET revoked=1 WHERE id=? AND user_id=?", (key_id, user_id))
    else:
        self._exec("UPDATE api_key SET revoked=1 WHERE id=?", (key_id,))


# Only digests reach these methods (`TinySesam` computes them with the pepper); what is allowed is decided there.

def app_password_add(self, user_id: int, name: str, digest: str, kid: str, hosts: list,
                     expires_at: Optional[int], ip) -> int:
    return self._exec("INSERT INTO app_password(user_id, name, digest, kid, hosts, created_at, created_ip, "
                      "expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (user_id, name, digest, kid, json.dumps(list(hosts)), _store._now(), ip, expires_at)).lastrowid


def app_password_by_digest(self, digest: str) -> Optional[sqlite3.Row]:
    return self._one("SELECT * FROM app_password WHERE digest=?", (digest,))


def app_password(self, pw_id: int) -> Optional[sqlite3.Row]:
    return self._one("SELECT * FROM app_password WHERE id=?", (int(pw_id),))


def app_passwords(self, user_id: Optional[int] = None) -> list:
    """The app passwords of an account — or of all accounts (`user_id=None`, admin panel), each with the name of
    its account. Newest first; revoked ones included."""
    q = ("SELECT p.*, u.username AS username FROM app_password p JOIN users u ON u.id = p.user_id")
    if user_id is None:
        return self._all(q + " ORDER BY p.created_at DESC, p.id DESC")
    return self._all(q + " WHERE p.user_id=? ORDER BY p.created_at DESC, p.id DESC", (int(user_id),))


def app_password_used(self, pw_id: int, ip, now: int, digest: Optional[str] = None,
                      kid: Optional[str] = None) -> None:
    """Remember the last use — and, after a pepper rotation, the digest made with the active pepper."""
    if digest and kid:
        self._exec("UPDATE app_password SET last_used=?, last_ip=?, digest=?, kid=? WHERE id=?",
                   (now, ip, digest, kid, int(pw_id)))
    else:
        self._exec("UPDATE app_password SET last_used=?, last_ip=? WHERE id=?", (now, ip, int(pw_id)))


def app_password_revoke(self, pw_id: int, reason: str, user_id: Optional[int] = None) -> bool:
    """Revoke one app password (of `user_id`, if given). True if it was valid until now."""
    q = "UPDATE app_password SET revoked_at=?, revoked_reason=? WHERE id=? AND revoked_at IS NULL"
    args: tuple = (_store._now(), reason, int(pw_id))
    if user_id is not None:
        q += " AND user_id=?"
        args += (int(user_id),)
    return self._exec(q, args).rowcount == 1


def app_passwords_revoke_all(self, user_id: int, reason: str) -> int:
    """Revoke every still valid app password of an account; returns how many."""
    return self._exec("UPDATE app_password SET revoked_at=?, revoked_reason=? WHERE user_id=? "
                      "AND revoked_at IS NULL", (_store._now(), reason, int(user_id))).rowcount


def app_passwords_active(self, user_id: int, now: Optional[int] = None) -> int:
    """How many app passwords of an account are valid (not revoked, not expired)."""
    now = _store._now() if now is None else now
    r = self._one("SELECT COUNT(*) AS n FROM app_password WHERE user_id=? AND revoked_at IS NULL "
                  "AND (expires_at IS NULL OR expires_at > ?)", (int(user_id), now))
    return int(r["n"]) if r else 0


def app_passwords_with_kid(self, kid: str, now: int) -> int:
    """Valid app passwords whose digest was made with pepper `kid` — what retiring that pepper would cut."""
    r = self._one("SELECT COUNT(*) AS n FROM app_password WHERE kid=? AND revoked_at IS NULL "
                  "AND (expires_at IS NULL OR expires_at > ?)", (kid, now))
    return int(r["n"]) if r else 0

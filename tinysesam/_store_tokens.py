"""The store part `tokens`: one-time tokens and shared resource secrets.

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .store import (
    json,
    replacement_name,
)


# ---------- Magic / one-time tokens ----------
def add_magic_token(self, token_hash, purpose, expires_at, user_id=None, email=None, payload=None):
    self._exec("INSERT INTO magic_token(token_hash, purpose, user_id, email, payload, created_at, expires_at) "
               "VALUES (?,?,?,?,?,?,?)",
               (token_hash, purpose, user_id, email, json.dumps(payload) if payload is not None else None,
                _store._now(), expires_at))


def get_magic_token(self, token_hash):
    return self._one("SELECT * FROM magic_token WHERE token_hash=?", (token_hash,))


def use_magic_token(self, token_hash) -> bool:
    """Mark as used atomically. True only on the FIRST valid redemption (one-shot)."""
    with self._writing():
        cur = self.db.execute(
            "UPDATE magic_token SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>=?",
            (_store._now(), token_hash, _store._now()))
        self.db.commit()
        return cur.rowcount == 1


def approve_qr_token(self, token_hash, user_id) -> bool:
    """Bind an open cross-device request (`purpose='qr_login'`, T-33) to the approving account —
    atomically and once: True only for the FIRST approval of a valid, unused request. From then
    on the row carries the account, so disabling it or a password reset discards it with the
    account's other open links (`revoke_user_magic_tokens`)."""
    with self._writing():
        cur = self.db.execute(
            "UPDATE magic_token SET user_id=? WHERE token_hash=? AND purpose='qr_login' "
            "AND user_id IS NULL AND used_at IS NULL AND expires_at>=?",
            (int(user_id), token_hash, _store._now()))
        self.db.commit()
        return cur.rowcount == 1


def expire_magic_token(self, token_hash) -> bool:
    """Let a still unused token expire immediately (sending failed, B6-12).

    Deliberately "expired" and not "used": `used_at` means "redeemed" — for a
    confirmation token that is "address proven". A never delivered link proved nothing,
    and the cleanup of unconfirmed accounts (`unconfirmed_accounts`) must see it as
    expired.
    """
    return self._exec("UPDATE magic_token SET expires_at=? WHERE token_hash=? AND used_at IS NULL",
                      (_store._now() - 1, token_hash)).rowcount == 1


def unconfirmed_accounts(self) -> list:
    """Accounts from a registration whose confirmation link has expired without them ever
    having been confirmed (R4-09). Only this combination counts — locked, never signed in,
    an unused and expired `verify_email` token, and NO valid or already
    redeemed one beside it. An existing account locked by the admin carries no such token
    and therefore stays untouched — and one with the operator mark (`disabled=2`) also
    when an app has sent it a confirmation link afterwards."""
    now = _store._now()
    return [r["id"] for r in self._all(
        "SELECT DISTINCT u.id FROM users u JOIN magic_token m ON m.user_id = u.id "
        "WHERE m.purpose = 'verify_email' AND m.used_at IS NULL AND m.expires_at < ? "
        "  AND u.is_owner = 0 "
        "  AND u.disabled = 1 AND u.first_login_at IS NULL "
        "  AND NOT EXISTS (SELECT 1 FROM magic_token m2 WHERE m2.user_id = u.id "
        "      AND m2.purpose = 'verify_email' AND (m2.used_at IS NOT NULL OR m2.expires_at >= ?))",
        (now, now))]


def gc_unconfirmed_accounts(self) -> int:
    """Remove never-confirmed accounts (R4-09) — call BEFORE `gc_magic_tokens`.

    The mark "never confirmed" is the expired confirmation token; if
    `gc_magic_tokens` clears it first, the account can no longer be recognised. Without this
    step an address that a stranger had registered and never confirmed stayed taken
    forever: the real owner got "email taken". Here and not in the manager,
    so that `tinysesam gc` (works directly on the store) runs the same order."""
    ids = self.unconfirmed_accounts()
    for uid in ids:
        # Via the one deletion path (H-13, integration findings 12/18): the registration of the
        # stranger including IP and the failed attempts of the real address holder would otherwise
        # keep standing under name and address — and the closing line would carry the clear name.
        self.remove_account(uid)
        self.audit_log("signup_expired", replacement_name(uid), None, f"uid={uid}")
    return len(ids)


def gc_magic_tokens(self) -> int:
    return self._exec("DELETE FROM magic_token WHERE expires_at < ? OR used_at IS NOT NULL", (_store._now(),)).rowcount


# ---------- Shared resource secrets ----------
def set_resource_secret(self, name, hash_, kind="pin", label=None):
    self._exec("INSERT INTO resource_secret(name, hash, kind, label, created_at) VALUES (?,?,?,?,?) "
               "ON CONFLICT(name) DO UPDATE SET hash=excluded.hash, kind=excluded.kind, label=excluded.label",
               (name, hash_, kind, label, _store._now()))


def get_resource_secret(self, name):
    return self._one("SELECT * FROM resource_secret WHERE name=?", (name,))


def list_resource_secrets(self):
    return self._all("SELECT name, kind, label, created_at FROM resource_secret ORDER BY name")


def delete_resource_secret(self, name):
    self._exec("DELETE FROM resource_secret WHERE name=?", (name,))
    self._exec("DELETE FROM resource_unlock WHERE resource=?", (name,))


# Only the hash here too. The token stood in plaintext in the file and was identical to the
# cookie: whoever read the file put the value into the browser and was in every unlocked
# scope for twelve hours — the same threat model that justifies the session switch,
# only one table further. The token has 256 bits, so sha256 suffices.
def add_resource_unlock(self, token, resource, expires_at):
    self._exec("INSERT OR REPLACE INTO resource_unlock(token, resource, expires_at) VALUES (?,?,?)",
               (self.session_hash(token), resource, expires_at))


def move_resource_unlocks(self, old_token, new_token) -> int:
    """Re-attach the approvals of a browser to a new token (F-01).

    Re-attach instead of copy: afterwards the old token holds nothing. If it was
    planted from outside, the planter comes away empty-handed; if it was the browser's own, the
    scopes this browser already had stay open."""
    if not old_token:
        return 0
    with self._writing():
        cur = self.db.execute("UPDATE OR REPLACE resource_unlock SET token=? WHERE token=?",
                              (self.session_hash(new_token), self.session_hash(old_token)))
        self.db.commit()
        return cur.rowcount


def delete_resource_unlocks(self, token) -> int:
    """End all approvals of this browser — on logout (F-08)."""
    if not token:
        return 0
    return self._exec("DELETE FROM resource_unlock WHERE token=?",
                      (self.session_hash(token),)).rowcount


def is_resource_unlocked(self, token, resource) -> bool:
    if not token:
        return False
    h = self.session_hash(token)
    r = self._one("SELECT expires_at FROM resource_unlock WHERE token=? AND resource=?", (h, resource))
    if not r:
        return False
    if r["expires_at"] < _store._now():
        self._exec("DELETE FROM resource_unlock WHERE token=? AND resource=?", (h, resource))
        return False
    return True


def gc_resource_unlocks(self) -> int:
    return self._exec("DELETE FROM resource_unlock WHERE expires_at < ?", (_store._now(),)).rowcount


def revoke_user_magic_tokens(self, user_id, purposes=None) -> int:
    """Discard still open one-time tokens of an account — all, or only the named purposes.

    Lock by the operator: a confirmation link sent before the lock would otherwise unlock
    the account again (`/auth/verify/…` lifts `disabled` — for the registration
    that is right, for a lock by the operator it is not), a sign-in link would have created a
    session. Reset, password change, "end sessions": an open address change
    from a taken-over session would otherwise survive the defence (attack round, finding 1)."""
    if purposes:
        ph = ",".join("?" * len(purposes))
        return self._exec(f"DELETE FROM magic_token WHERE user_id=? AND used_at IS NULL "
                          f"AND purpose IN ({ph})", (user_id, *purposes)).rowcount
    return self._exec("DELETE FROM magic_token WHERE user_id=? AND used_at IS NULL",
                      (user_id,)).rowcount

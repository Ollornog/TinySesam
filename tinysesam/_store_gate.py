"""The store part `gate`: per-application approvals, sign-out of one application, app-host links (T-26), ID token hints.

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .store import (  # noqa: F401
    Optional,
    json,
    now,
)
from .store import Store


# The key is the **hash** of the session, not the plaintext — the same rule as in
# `session`: whoever reads the file thereby gets no session that can be taken over.
def set_oidc_session(self, handle, client, sub, refresh, client_id: Optional[str] = None) -> None:
    """Store the refresh token of an OIDC session for THIS client — encrypted (4a).

    One row per client: with several applications, a later login via another
    client must not overwrite the re-check of the first — otherwise the user would choose
    which provider entry is still re-checked (attack on the second round, finding 7)."""
    if self.vault is None:
        raise RuntimeError("Refresh tokens are only stored encrypted (vault.Vault).")
    self._exec("INSERT INTO oidc_session(token_hash, client, sub, refresh, checked_at, client_id, success_at) "
               "VALUES (?,?,?,?,?,?,?) ON CONFLICT(token_hash, client) DO UPDATE SET sub=excluded.sub, "
               "refresh=excluded.refresh, checked_at=excluded.checked_at, client_id=excluded.client_id, "
               "success_at=excluded.success_at",
               (self._handle(handle), client, sub, self._seal(refresh, "oidc_session.refresh", client, sub),
                _store._now(), client_id, _store._now()))


def get_oidc_sessions(self, handle) -> list:
    """The OIDC rows of a session — the refresh token ENCRYPTED (it is decrypted
    only when exchanging; a request before the deadline expires does not touch the key)."""
    return [dict(z) for z in self._all("SELECT * FROM oidc_session WHERE token_hash=?",
                                      (self._handle(handle),))]


def get_oidc_session(self, handle, client="*") -> Optional[dict]:
    """One OIDC row, with the refresh token decrypted, or None (for tools and tests)."""
    z = self._one("SELECT * FROM oidc_session WHERE token_hash=? AND client=?", (self._handle(handle), client))
    if z is None:
        return None
    d = dict(z)
    if self.vault is not None:
        d["refresh"] = self.oidc_refresh_plain(d)
    return d


def oidc_refresh_plain(self, row) -> Optional[str]:
    """The refresh token of an `oidc_session` row, decrypted — bound to the row's client and subject."""
    return self._open(row["refresh"], "oidc_session.refresh", row["client"], row["sub"])


def claim_oidc_session(self, handle, client, old: int, now: int) -> bool:
    """Claim the due exchange for EXACTLY one request: `checked_at` from `old` to
    `now`, only if it is still `old`. Several simultaneous requests (also across workers) —
    only one exchanges. Otherwise all would exchange the same refresh token, and a provider with
    token rotation rejected the second exchange: the session ended for no reason (finding 5)."""
    return self._exec("UPDATE oidc_session SET checked_at=? WHERE token_hash=? AND client=? "
                      "AND checked_at=?", (int(now), self._handle(handle), client, int(old))).rowcount == 1


def oidc_session_checked(self, handle, client, when: int, new_refresh=None,
                          old_encrypted: Optional[str] = None, success: bool = False) -> bool:
    """Record the exchange; a newly issued refresh token replaces the old one (rotation).
    Return value: whether the row was still there (the session may have ended meanwhile).

    With `old_encrypted` (the stored, encrypted token with which the exchange was
    made) the row is found through it instead of through the handle: if the session gets a new token
    during the exchange (step-up, completion of a factor), the row hangs on the new
    handle — the old one would hit nothing, and the refresh token rotated by the provider would be
    lost; the next exchange with the old one would be a no at PocketID. The ciphertext is
    unique through its nonce."""
    where, value = ("refresh=?", old_encrypted) if old_encrypted else ("token_hash=?", self._handle(handle))
    # `success`: the provider has just said yes — state for the upper limit without a re-check.
    # `checked_at` alone is not suitable for that: after an "error" it stands at "in a minute".
    extra = ", success_at=?" if success else ""
    success_value = (int(when),) if success else ()
    if new_refresh and self.vault is not None:
        row = self._one(f"SELECT sub FROM oidc_session WHERE {where} AND client=?", (value, client))
        if row is None:
            return False
        return self._exec(f"UPDATE oidc_session SET checked_at=?, refresh=?{extra} WHERE {where} AND client=?",
                          (int(when), self._seal(new_refresh, "oidc_session.refresh", client, row["sub"]),
                           *success_value, value, client)).rowcount > 0
    return self._exec(f"UPDATE oidc_session SET checked_at=?{extra} WHERE {where} AND client=?",
                      (int(when), *success_value, value, client)).rowcount > 0


def move_oidc_session(self, old, new) -> None:
    """Attach the OIDC rows to a new session (new token at the completion of the chain) —
    BEFORE deleting the old ones, otherwise the foreign key would take them along."""
    self._exec("UPDATE oidc_session SET token_hash=? WHERE token_hash=?",
               (self._handle(new), self._handle(old)))


# ---------- Gate: signed out of one application only (T-22) ----------
def gate_sign_out(self, handle, host: str) -> None:
    self._exec("INSERT OR REPLACE INTO gate_signed_out(token_hash, host, at) VALUES (?,?,?)",
               (self._handle(handle), str(host).lower(), _store._now()))


def gate_is_signed_out(self, handle, host: str) -> bool:
    return bool(self._one("SELECT 1 FROM gate_signed_out WHERE token_hash=? AND host=?",
                          (self._handle(handle), str(host).lower())))


def gate_resume(self, handle, host: str) -> int:
    return self._exec("DELETE FROM gate_signed_out WHERE token_hash=? AND host=?",
                      (self._handle(handle), str(host).lower())).rowcount


# ---------- Connection of an app host to the central session (T-26) ----------
def create_gate_link(self, link_hash: str, handle, host: str) -> None:
    self._exec("INSERT INTO gate_link(link_hash, token_hash, host, created_at) VALUES (?,?,?,?)",
               (link_hash, self._handle(handle), str(host).lower(), _store._now()))


def gate_link_handle(self, link_hash: str, host: str) -> Optional[str]:
    """The session handle behind this connection — only for ITS host, otherwise None."""
    r = self._one("SELECT token_hash FROM gate_link WHERE link_hash=? AND host=?", (link_hash, str(host).lower()))
    return r["token_hash"] if r else None


def remove_gate_link(self, link_hash: str) -> int:
    return self._exec("DELETE FROM gate_link WHERE link_hash=?", (link_hash,)).rowcount


# ---------- ID token as a sign-out hint (T-22) ----------
def set_oidc_id_token(self, handle, client: str, id_token: str) -> None:
    if self.vault is None:
        raise RuntimeError("ID tokens are only stored encrypted (vault.Vault).")
    h = self._handle(handle)
    owner = self._one("SELECT user_id FROM session WHERE token_hash=?", (h,))
    if owner is None:
        return          # the session is gone — the row would hang on nothing (foreign key)
    self._exec("INSERT OR REPLACE INTO oidc_id_token(token_hash, client, id_token) VALUES (?,?,?)",
               (h, client, self._seal(id_token, "oidc_id_token.id_token", client, owner["user_id"])))


def get_oidc_id_token(self, handle) -> Optional[tuple]:
    """(client, id_token) of this session's sign-in, decrypted — or None. Bound to client and account (the
    session handle rotates, the account stays)."""
    r = self._one("SELECT t.client, t.id_token, s.user_id FROM oidc_id_token t "
                  "JOIN session s ON s.token_hash = t.token_hash WHERE t.token_hash=?", (self._handle(handle),))
    if not r or self.vault is None:
        return None
    return r["client"], self._open(r["id_token"], "oidc_id_token.id_token", r["client"], r["user_id"])


def put_oidc_grant(self, token_hash: str, client: str, now: int, roles=None) -> None:
    """Enter or confirm an approval. `granted_at` stays on a confirmation —
    otherwise nobody could answer the question "since when may this session enter this application"."""
    self._exec(
        "INSERT INTO oidc_grant(token_hash, client, granted_at, checked_at, roles) VALUES (?,?,?,?,?)"
        " ON CONFLICT(token_hash, client) DO UPDATE SET checked_at=excluded.checked_at,"
        " roles=excluded.roles",
        (token_hash, client, now, now, json.dumps(list(roles or []))))


def confirm_oidc_grant(self, token_hash: str, client: str, now: int, roles=None) -> int:
    """Confirm an EXISTING approval (B-6): a successful refresh exchange for this client is
    the provider's yes for this application. Never creates one — an approval withdrawn by the
    operator (`drop_oidc_grant`) or never granted stays absent. `roles=None` keeps the stored ones."""
    if roles is None:
        return self._exec("UPDATE oidc_grant SET checked_at=? WHERE token_hash=? AND client=?",
                          (now, token_hash, client)).rowcount
    return self._exec("UPDATE oidc_grant SET checked_at=?, roles=? WHERE token_hash=? AND client=?",
                      (now, json.dumps(list(roles)), token_hash, client)).rowcount


def get_oidc_grant(self, token_hash: str, client: str) -> Optional[dict]:
    r = self._one("SELECT * FROM oidc_grant WHERE token_hash=? AND client=?", (token_hash, client))
    if not r:
        return None
    d = dict(r)
    try:
        d["roles"] = json.loads(d.get("roles") or "[]")
    except Exception:
        d["roles"] = []
    return d


def list_oidc_grants(self, token_hash: str) -> list:
    return [dict(r) for r in self._all(
        "SELECT client, granted_at, checked_at FROM oidc_grant WHERE token_hash=?"
        " ORDER BY granted_at", (token_hash,))]


def drop_oidc_grant(self, token_hash: str, client: str) -> int:
    """Withdraw an approval. Exactly one — the session and the other applications stay;
    that is the difference between "the provider says no to this app" and "sign out"."""
    return self._exec("DELETE FROM oidc_grant WHERE token_hash=? AND client=?",
                      (token_hash, client)).rowcount


def drop_oidc_grants_for_user(self, user_id: int, client: Optional[str] = None) -> int:
    """Withdraw all approvals of an account (optionally only for one application). The way for
    the operator when the provider has excluded someone and it should take effect immediately,
    without ending the session itself."""
    if client is None:
        return self._exec(
            "DELETE FROM oidc_grant WHERE token_hash IN (SELECT token_hash FROM session WHERE user_id=?)",
            (user_id,)).rowcount
    return self._exec(
        "DELETE FROM oidc_grant WHERE client=? AND token_hash IN"
        " (SELECT token_hash FROM session WHERE user_id=?)", (client, user_id)).rowcount

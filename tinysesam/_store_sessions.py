"""The store part `sessions`: sessions and the keyed token digests (T-71, T-72).

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .store import (
    hashlib,
    json,
    secrets,
)
import sqlite3
from typing import Optional


def session_hash(self, token: str) -> str:
    """The stored digest of a browser token (session, app-host link, area unlock).

    With one pepper it is the HMAC with it. After `tinysesam keys rotate --purpose oauth-pepper` a digest made
    with a previous pepper keeps naming its row until that row ends: the lookup takes the candidate that exists,
    a new row gets the active pepper. Without a pepper the store refuses — a plain digest is exactly what T-71
    closed, and a silent fallback to it would reopen it."""
    if not self.session_peppers:
        raise RuntimeError("Store.session_peppers is not set: session digests need the pepper keyring "
                           "(TinySesam sets it at startup).")
    plain = hashlib.sha256((token or "").encode()).hexdigest()
    candidates = [self._session_digest(p, plain) for p in self.session_peppers]
    if len(candidates) == 1:
        return candidates[0]
    marks = ",".join("?" * len(candidates))
    for table, column in (("session", "token_hash"), ("gate_link", "link_hash"), ("resource_unlock", "token")):
        r = self._one(f"SELECT {column} AS h FROM {table} WHERE {column} IN ({marks}) LIMIT 1", candidates)
        if r is not None:
            return str(r["h"])
    return candidates[0]


def token_digests(self, raw: str, kind: str) -> list:
    """Every candidate digest of `raw` for `kind`, the active pepper first — for a value compared in place (the QR
    device secret in a payload). Refuses without the pepper, like `session_hash`."""
    if kind not in self.TOKEN_KINDS:
        raise ValueError(f"unknown token kind {kind!r}")
    if not self.session_peppers:
        raise RuntimeError("Store.session_peppers is not set: token digests need the pepper keyring "
                           "(TinySesam sets it at startup).")
    return [self._token_digest(p, kind, raw) for p in self.session_peppers]


def token_digest(self, raw: str, kind: str) -> str:
    """The stored digest of an API key (`kind="apikey"`) or a one-time token (`"magic"`).

    With one pepper the HMAC with it. After a pepper rotation a row made with a previous pepper keeps being found:
    the candidate that exists is returned, a new row gets the active pepper (an API key moves to it on its next use,
    `rewrite_api_key_digest`)."""
    candidates = self.token_digests(raw, kind)
    where = self.TOKEN_KINDS[kind]
    if len(candidates) == 1 or where is None:
        return candidates[0]
    table, column = where
    r = self._one(f"SELECT {column} AS h FROM {table} WHERE {column} IN ({','.join('?' * len(candidates))}) "
                  "LIMIT 1", candidates)
    return str(r["h"]) if r is not None else candidates[0]


def rewrite_api_key_digest(self, old: str, new: str) -> int:
    """Move an API key found with a previous pepper to the active one (compare-and-swap on the old digest)."""
    if old == new:
        return 0
    return self._exec("UPDATE api_key SET key_hash=?, last_used=? WHERE key_hash=?", (new, _store._now(), old)).rowcount


def tokens_live_before(self, when: int, now: int) -> tuple:
    """(one-time tokens, API keys) made up to `when` that may still carry a digest of a pepper retired at `when`:
    open one-time tokens not yet expired, and API keys neither revoked, expired nor used since (T-72)."""
    magic = self._one("SELECT COUNT(*) AS n FROM magic_token WHERE created_at <= ? AND expires_at > ? "
                      "AND used_at IS NULL", (when, now))["n"]
    keys = self._one("SELECT COUNT(*) AS n FROM api_key WHERE created_at <= ? AND revoked = 0 "
                     "AND (expires_at IS NULL OR expires_at > ?) AND (last_used IS NULL OR last_used <= ?)",
                     (when, now, when))["n"]
    return int(magic), int(keys)


def sessions_live_before(self, when: int, now: int) -> int:
    """Sessions and app-host links created up to `when` that still run — what a pepper retired at `when` would
    end (their digest was made with it, T-71)."""
    return int(self._one("SELECT (SELECT COUNT(*) FROM session WHERE created_at <= ? AND expires_at > ?) + "
                         "(SELECT COUNT(*) FROM gate_link l JOIN session s ON s.token_hash = l.token_hash "
                         "WHERE l.created_at <= ? AND s.expires_at > ?) AS n", (when, now, when, now))["n"])


def create_session(self, user_id, ttl_seconds, mfa_ok, method, ip=None, ua=None, remember=True,
                   factors=None) -> str:
    token = secrets.token_urlsafe(32)
    now = _store._now()
    self._exec("INSERT INTO session(token_hash, user_id, created_at, expires_at, mfa_ok, mfa_at, "
               "method, factors_done, remember, ip, user_agent, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
               (self.session_hash(token), user_id, now, now + ttl_seconds, 1 if mfa_ok else 0,
                (now if mfa_ok else None), method, json.dumps(list(factors or [])),
                1 if remember else 0, ip, ua, now))
    return token


def set_session_factors(self, handle, factors, mfa_ok=None):
    h = self._handle(handle)
    if mfa_ok is None:
        self._exec("UPDATE session SET factors_done=?, mfa_at=? WHERE token_hash=?",
                   (json.dumps(list(factors)), _store._now(), h))
    else:
        self._exec("UPDATE session SET factors_done=?, mfa_ok=?, mfa_at=? WHERE token_hash=?",
                   (json.dumps(list(factors)), 1 if mfa_ok else 0, _store._now(), h))


def get_session(self, token) -> Optional[sqlite3.Row]:
    if not token:
        return None
    return self.get_session_by_handle(self.session_hash(token))


def get_session_by_handle(self, handle) -> Optional[sqlite3.Row]:
    """Like `get_session`, but via the handle (`token_hash`) — for paths that do not know the session
    from their own cookie (the connection of an app host, T-26). The same checks:
    expiry, inactivity, updating `zuletzt`."""
    h = str(handle or "")
    if len(h) != 64:
        return None
    r = self._one("SELECT * FROM session WHERE token_hash=?", (h,))
    if not r:
        return None
    now = _store._now()
    if r["expires_at"] < now:
        self.delete_session_by_handle(h)
        return None
    # Inactivity (F-05): in addition to the absolute lifetime. An expired session is
    # deleted, not only rejected — otherwise it would come back to life with the next access.
    # The long limit only if someone EXPLICITLY chose "stay signed in". A
    # session that is permanent only because the path knows no choice (OIDC, passkey,
    # sign-in link) or the checkbox is switched off would otherwise never get an idle end
    # (attack on the second round, finding 9).
    limit = self.idle_sec[1 if (r["remember"] and r["stay_chosen"]) else 0]
    last = r["last_seen"] if r["last_seen"] is not None else r["created_at"]
    if limit and now - int(last) > limit:
        self.delete_session_by_handle(h)
        return None
    if now - int(last) >= self.IDLE_STEP_SEC:
        self._exec("UPDATE session SET last_seen=? WHERE token_hash=?", (now, r["token_hash"]))
    return r


def set_session_stay(self, handle):
    """Record: "stay signed in" was explicitly chosen (F-05)."""
    self._exec("UPDATE session SET stay_chosen=1 WHERE token_hash=?", (self._handle(handle),))


def set_session_end_others(self, handle):
    """Record: if this (half) session becomes full, the account's other ones end (limit d)."""
    self._exec("UPDATE session SET end_others=1 WHERE token_hash=?", (self._handle(handle),))


def set_session_mfa(self, handle, ok=True):
    self._exec("UPDATE session SET mfa_ok=?, mfa_at=? WHERE token_hash=?",
               (1 if ok else 0, (_store._now() if ok else None), self._handle(handle)))


def backdate_confirmation(self, token, at: int) -> None:
    """Move the confirmation time (`mfa_at`) of a session back to `at` — never forward (T-49).

    For a sign-in through a provider whose own sign-in lies further back (`auth_time`): the session is new, the
    confirmation is not."""
    self._exec("UPDATE session SET mfa_at=MIN(COALESCE(mfa_at, ?), ?) WHERE token_hash=?",
               (int(at), int(at), self.session_hash(token)))


def delete_session(self, token):
    """Plaintext token (from the cookie) — for logout."""
    self._exec("DELETE FROM session WHERE token_hash=?", (self.session_hash(token),))


def delete_session_by_handle(self, handle):
    """Handle from a session row — for the admin panel and "end other sessions"."""
    h = self._handle(handle)
    # A superseded token in the grace period (A-6) belongs to this session and goes with it.
    self._exec("DELETE FROM session WHERE token_hash=? OR successor=?", (h, h))


def rotate_session(self, handle, mercy_sec: int = 0) -> Optional[str]:
    """Give the session a new token without otherwise changing it (F-06).

    Lifetime, factors and `created_at` stay — a step-up is meant to renew the token, not
    extend the absolute lifetime. The OIDC approvals hang on the handle by foreign key
    and move along; hence a new row, re-attach the approvals, delete the old row, all
    in one transaction. Returns the new plaintext token, or None if the
    session does not (any longer) exist.

    `mercy_sec` (A-6, PO decision 2026-09-25): the old token then remains valid for that many
    seconds — a request that was already under way at the moment of the step-up (second tab,
    background loading) would otherwise fail once. It then applies WITHOUT step-up freshness (`mfa_at`
    empty): whoever read along the old token gets no freshly confirmed rights, only
    the deadline. It points to its successor and ends with it (`delete_session_by_handle`).
    An already superseded token is not rotated again."""
    old = self._handle(handle)
    token = secrets.token_urlsafe(32)
    new = self.session_hash(token)
    columns = ("user_id, created_at, expires_at, mfa_ok, mfa_at, method, factors_done, "
               "remember, ip, user_agent, last_seen, stay_chosen")
    with self._lock:
        try:
            cur = self.db.execute(
                f"INSERT INTO session(token_hash, {columns}) SELECT ?, {columns} FROM session "
                "WHERE token_hash=? AND successor IS NULL", (new, old))
            if cur.rowcount != 1:
                self.db.rollback()
                return None
            self.db.execute("UPDATE oidc_grant SET token_hash=? WHERE token_hash=?", (new, old))
            self.db.execute("UPDATE oidc_session SET token_hash=? WHERE token_hash=?", (new, old))
            self.db.execute("UPDATE gate_signed_out SET token_hash=? WHERE token_hash=?", (new, old))
            self.db.execute("UPDATE oidc_id_token SET token_hash=? WHERE token_hash=?", (new, old))
            self.db.execute("UPDATE gate_link SET token_hash=? WHERE token_hash=?", (new, old))
            if mercy_sec > 0:
                self.db.execute("UPDATE session SET expires_at=MIN(expires_at, ?), mfa_at=NULL, "
                                "successor=? WHERE token_hash=?", (_store._now() + int(mercy_sec), new, old))
                # An earlier predecessor that points to the old token now points to the new one —
                # otherwise it would survive a sign-out of the new session.
                self.db.execute("UPDATE session SET successor=? WHERE successor=?", (new, old))
            else:
                self.db.execute("DELETE FROM session WHERE token_hash=?", (old,))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
    return token


def delete_user_sessions(self, user_id):
    self._exec("DELETE FROM session WHERE user_id=?", (user_id,))


def delete_user_sessions_except(self, user_id, keep_handle):
    """End all sessions of a user EXCEPT one (e.g. the current one on a self password change).

    `keep_handle` is the `token_hash` from the session row, not the cookie."""
    self._exec("DELETE FROM session WHERE user_id=? AND token_hash!=?", (user_id, keep_handle or ""))


def gc_sessions(self) -> int:
    return self._exec("DELETE FROM session WHERE expires_at < ?", (_store._now(),)).rowcount


def list_sessions(self, user_id=None):
    # Superseded tokens in the grace period (A-6) are not a session of their own.
    if user_id is not None:
        return self._all("SELECT * FROM session WHERE user_id=? AND successor IS NULL "
                         "ORDER BY created_at DESC", (user_id,))
    return self._all("SELECT * FROM session WHERE successor IS NULL ORDER BY created_at DESC")

"""The store part `federation`: OIDC links, the first sign-in and enrollment window, federated identities (F-11).

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .store import (
    time,
)
from typing import Optional


# ---------- OIDC link ----------
def link_oidc(self, issuer, subject, user_id):
    self._exec("INSERT OR REPLACE INTO oidc_identity(issuer, subject, user_id) VALUES (?,?,?)",
               (issuer, subject, user_id))


# ---------- First login and enrollment window (R3-1) ----------
def mark_first_login(self, user_id: int, now: int) -> bool:
    """Record the first complete login — only the first time (idempotent).

    Return value: True if this call set it. The condition is in the SQL, not
    before it: two simultaneous sign-ins of the same account (two devices, two workers)
    would otherwise both read, both write, and the time would be the later one."""
    return self._exec("UPDATE users SET first_login_at=? WHERE id=? AND first_login_at IS NULL",
                      (now, user_id)).rowcount > 0


def mark_login(self, user_id: int, now: int) -> bool:
    """Record a complete sign-in: `last_login_at` every time, `first_login_at` only the first time (schema 23).

    One transaction, the condition for the first time in the SQL (see `mark_first_login`). Returns True if this
    call set `first_login_at`."""
    with self._writing():
        first = self.db.execute("UPDATE users SET first_login_at=? WHERE id=? AND first_login_at IS NULL",
                                (now, user_id)).rowcount > 0
        self.db.execute("UPDATE users SET last_login_at=? WHERE id=?", (now, user_id))
        self.db.commit()
    return first


def clear_sign_in_factors(self, user_id: int) -> dict:
    """Delete every sign-in factor TinySesam keeps for an account — password, PIN, TOTP with its recovery codes,
    passkeys — in ONE transaction (approval type `tinysesam.account.reset_access`): either all are gone or none.
    Federated sign-ins (OIDC, SAML, LDAP) live at the provider and stay. Returns the counts per kind."""
    uid = int(user_id)
    # Literal statements, no table name from a variable: the deletion-path guard (N-8, test_audit_round2) reads
    # them and admits this method as a building block that deletes passkeys.
    statements = (("password", "DELETE FROM password_cred WHERE user_id=?"),
                  ("pin", "DELETE FROM pin_cred WHERE user_id=?"),
                  ("totp", "DELETE FROM totp_cred WHERE user_id=?"),
                  ("recovery_codes", "DELETE FROM recovery_code WHERE user_id=?"),
                  ("passkeys", "DELETE FROM webauthn_cred WHERE user_id=?"))
    with self._writing():
        counts = {kind: self.db.execute(sql, (uid,)).rowcount for kind, sql in statements}
        self.db.execute("UPDATE users SET password_must_change=0 WHERE id=?", (uid,))
        self.db.commit()
    return counts


def set_password_must_change(self, user_id: int, value: bool) -> None:
    """Mark the password as a start secret set by an administrator (T-46) — or clear the mark."""
    self._exec("UPDATE users SET password_must_change=? WHERE id=?", (1 if value else 0, user_id))


def password_must_change(self, user_id) -> bool:
    """Is the account's password a start secret that has to be replaced at the next sign-in?"""
    row = self._one("SELECT password_must_change FROM users WHERE id=?", (user_id,))
    return bool(row and row["password_must_change"])


def set_mfa_enroll_until(self, user_id: int, until: Optional[int]) -> None:
    """Open the enrollment window (timestamp) or close it (None)."""
    self._exec("UPDATE users SET mfa_enroll_until=? WHERE id=?", (until, user_id))


def is_oidc_account(self, user_id) -> bool:
    """Is this account bound to an OIDC identity (finding 8)?"""
    return bool(self._one("SELECT 1 FROM oidc_identity WHERE user_id=? LIMIT 1", (user_id,)))


def confirm_idp(self, user_id, asked_at: Optional[int] = None) -> bool:
    """The provider has confirmed the account (login via it, refresh exchange with yes).

    `asked_at` is the time at which the question to the provider WENT OUT. A no that was
    recorded after that stays: two exchanges run in parallel (two sessions,
    two clients), and a yes that was answered before the lock but applied after the no
    would otherwise wake the keys of a locked account (attack on the third round).
    Return value: whether anything was written."""
    now = _store._now()
    asked = int(asked_at if asked_at is not None else now)
    return self._exec(
        "UPDATE users SET idp_confirmed_at=? WHERE id=? AND (idp_confirmed_at IS NULL "
        "OR idp_confirmed_at > 0 OR -idp_confirmed_at < ?)", (now, user_id, asked)).rowcount > 0


def idp_refused(self, user_id) -> None:
    """The provider said no: the API keys of the account are dormant until the next
    confirmation (finding 8). Stored as a NEGATIVE time of the no — NULL means "never
    confirmed", ≤ 0 "refused", and the time decides whether a later-applied yes
    is younger (`confirm_idp`)."""
    self._exec("UPDATE users SET idp_confirmed_at=? WHERE id=?", (-max(_store._now(), 1), user_id))


def oidc_session_handle(self, client, old_encrypted) -> Optional[str]:
    """TODAY's handle of the session whose row carries this (encrypted) token."""
    r = self._one("SELECT token_hash FROM oidc_session WHERE client=? AND refresh=?",
                  (client, old_encrypted))
    return r["token_hash"] if r else None


def discard_oidc_session(self, handle, client) -> None:
    """Discard an OIDC row without a configured client — the session itself stays."""
    self._exec("DELETE FROM oidc_session WHERE token_hash=? AND client=?", (self._handle(handle), client))


def get_oidc_user(self, issuer, subject) -> Optional[int]:
    r = self._one("SELECT user_id FROM oidc_identity WHERE issuer=? AND subject=?", (issuer, subject))
    return r["user_id"] if r else None


# ---------- Federated identities via a stable identifier (F-11) ----------
def link_federated(self, source: str, identifier: str, user_id: int, now: int) -> None:
    """Bind a foreign identity to a local account (or renew the binding)."""
    self._exec("INSERT OR REPLACE INTO federated_identity(source, identifier, user_id, bound_at)"
               " VALUES (?,?,?,?)", (source, identifier, user_id, now))


def get_federated_user(self, source: str, identifier: str) -> Optional[int]:
    r = self._one("SELECT user_id FROM federated_identity WHERE source=? AND identifier=?",
                  (source, identifier))
    return r["user_id"] if r else None


def get_federated_identifier(self, source: str, user_id: int) -> Optional[str]:
    """The identifier with which this account is bound for this source — None if none.

    The way back is the actual bolt: if an account already carries an identifier, it must
    **not** be bound to a second one. That is exactly what would happen if a deleted account
    were recreated under the same name in the directory."""
    r = self._one("SELECT identifier FROM federated_identity WHERE source=? AND user_id=?",
                  (source, user_id))
    return r["identifier"] if r else None


def has_foreign_identity(self, user_id: int) -> bool:
    """Is this account bound to any foreign identity (OIDC, LDAP, SAML)?"""
    return bool(self._one("SELECT 1 FROM oidc_identity WHERE user_id=? "
                          "UNION ALL SELECT 1 FROM federated_identity WHERE user_id=? LIMIT 1",
                          (user_id, user_id)))


#: The origins an account can have, in the order they are shown (T-99, ADR-18).
ACCOUNT_SOURCES = ("local", "oidc", "saml", "ldap")


def account_sources(self, user_ids=None) -> dict:
    """{account id: its origins} (T-99, ADR-18 "the origin is a visible attribute"), in the order of `ACCOUNT_SOURCES`.

    `oidc`, `saml`, `ldap`: the account is bound to an identity of that provider (`oidc_identity`, `federated_identity`,
    an origin placeholder included), or — without any binding — the provider created its name (`name_source`).
    `local`: it has a way in of its own — a password, a passkey or a PIN — or no provider at all (a sign-in link then).
    Two or more is a mixed account. One query for all accounts (`user_ids` None) or the given ones; no decision of
    TinySesam reads it, it is shown only."""
    where, args = "", ()  # type: tuple[str, tuple]
    if user_ids is not None:
        ids = [int(u) for u in user_ids]
        if not ids:
            return {}
        where, args = f" WHERE u.id IN ({','.join('?' * len(ids))})", tuple(ids)
    rows = self._all(
        "SELECT u.id, u.name_source, "
        "EXISTS (SELECT 1 FROM oidc_identity o WHERE o.user_id = u.id) AS oidc, "
        "EXISTS (SELECT 1 FROM federated_identity f WHERE f.user_id = u.id AND f.source = 'saml') AS saml, "
        "EXISTS (SELECT 1 FROM federated_identity f WHERE f.user_id = u.id AND f.source = 'ldap') AS ldap, "
        "(EXISTS (SELECT 1 FROM password_cred p WHERE p.user_id = u.id) "
        " OR EXISTS (SELECT 1 FROM webauthn_cred w WHERE w.user_id = u.id) "
        " OR EXISTS (SELECT 1 FROM pin_cred n WHERE n.user_id = u.id)) AS own "
        "FROM users u" + where, args)
    out = {}
    for r in rows:
        found = {s for s in ("oidc", "saml", "ldap") if r[s]}
        if not found and r["name_source"] in ("oidc", "saml", "ldap"):
            found.add(r["name_source"])
        if r["own"] or not found:
            found.add("local")
        out[int(r["id"])] = [s for s in ACCOUNT_SOURCES if s in found]
    return out


def unlink_oidc(self, user_id: int) -> int:
    """Release every OIDC identity of an account (T-99: the person unlinks it). Returns how many were released."""
    return self._exec("DELETE FROM oidc_identity WHERE user_id=?", (int(user_id),)).rowcount


def close_name_binding(self, source: str, user_id: int) -> None:
    """The person released this source's identity themselves (T-99): a row in `name_binding` with `until` = 0 — the
    next sign-in never binds the account by its name again (`_rebinding_reason` -> `unlinked_by_holder`). Lifted when
    the person links again (`rebind` deletes the row) or the operator opens the binding (`federation_unbind` replaces
    it); deleted with the account."""
    self._exec("INSERT OR REPLACE INTO name_binding(source, user_id, until) VALUES (?,?,0)", (source, int(user_id)))


def name_binding_closed(self, source: str, user_id: int) -> bool:
    """Has the person released this source's identity themselves (`close_name_binding`)?"""
    return self._one("SELECT 1 AS x FROM name_binding WHERE source=? AND user_id=? AND until = 0",
                     (source, int(user_id))) is not None


def unlink_federated(self, source: str, user_id: int) -> int:
    """Release the binding of an account for a source (operator path after a move)."""
    return self._exec("DELETE FROM federated_identity WHERE source=? AND user_id=?",
                      (source, user_id)).rowcount


def rebind(self, source: str, identifier: str, user_id: int, now: int) -> bool:
    """Bind an account to an identifier that belongs to nobody yet — or do nothing (G1).

    For the binding of existing accounts (`TinySesam.federation_bind_existing`), which runs through a whole
    directory between check and write. `link_federated` replaces a row with
    the same identifier (`INSERT OR REPLACE`) — here that would take its binding away from an account that has
    meanwhile signed in. Hence in ONE transaction: if the identifier already belongs
    to an account or this account already carries a real identifier, everything stays as it is
    (`False`). Otherwise an origin placeholder yields, the binding is created, and an open
    name binding (`name_binding`) is done."""
    with self._writing():
        occupied = self.db.execute(
            "SELECT 1 FROM federated_identity WHERE source=? AND (identifier=? OR "
            "(user_id=? AND substr(identifier, 1, ?) <> ?)) LIMIT 1",
            (source, identifier, user_id, len(self.WITHOUT_IDENTIFIER), self.WITHOUT_IDENTIFIER)).fetchone()
        if occupied is not None:
            return False
        self.db.execute("DELETE FROM federated_identity WHERE source=? AND user_id=?", (source, user_id))
        self.db.execute("INSERT INTO federated_identity(source, identifier, user_id, bound_at) "
                        "VALUES (?,?,?,?)", (source, identifier, user_id, now))
        self.db.execute("DELETE FROM name_binding WHERE source=? AND user_id=?", (source, user_id))
        self.db.commit()
        self._written = time.monotonic()
        self._clock_record()
    return True


def without_binding(self, source: str) -> list:
    """The accounts without a real identifier for this source — no row or only the
    origin placeholder —, excluding service accounts (G1). With `has_password` (local password)."""
    return self._all(
        "SELECT u.*, EXISTS (SELECT 1 FROM password_cred p WHERE p.user_id = u.id) AS has_password "
        "FROM users u WHERE u.is_service = 0 AND NOT EXISTS (SELECT 1 FROM federated_identity f "
        "WHERE f.source = ? AND f.user_id = u.id AND substr(f.identifier, 1, ?) <> ?) ORDER BY u.id",
        (source, len(self.WITHOUT_IDENTIFIER), self.WITHOUT_IDENTIFIER))


def open_name_binding(self, source: str, user_id: int, until: int) -> None:
    """Open the binding via the name for this account until `bis` (G1, `federation_unbind`)."""
    self._exec("INSERT OR REPLACE INTO name_binding(source, user_id, until) VALUES (?,?,?)",
               (source, user_id, int(until)))


def name_binding_unclosed(self, source: str, user_id: int, now: int) -> bool:
    """Has the operator opened the binding via the name for this account (and is it still running)?"""
    return self._one("SELECT 1 AS x FROM name_binding WHERE source=? AND user_id=? AND until > ?",
                     (source, user_id, int(now))) is not None


def name_binding_close(self, source: str, user_id: int) -> None:
    """The opened binding via the name is done (the binding stands)."""
    self._exec("DELETE FROM name_binding WHERE source=? AND user_id=?", (source, user_id))


def federation_since(self, source: str, now: int) -> int:
    """The marker of a federated source (`federation_since:<quelle>`): from when the deadline for
    the binding via the name runs (G1). Set to `now` on the first call, never
    again afterwards — a marker that were set anew on every start would give every restart a
    new deadline. `INSERT OR IGNORE`: if several workers start at the same time, the first wins, and
    all afterwards read the same value."""
    key_name = f"federation_since:{source}"
    z = self._one("SELECT value FROM setting WHERE key=?", (key_name,))
    if z is None:
        self._exec("INSERT OR IGNORE INTO setting(key, value) VALUES (?,?)", (key_name, str(int(now))))
        z = self._one("SELECT value FROM setting WHERE key=?", (key_name,))
    return int(z["value"])

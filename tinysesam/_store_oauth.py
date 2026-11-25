"""The store part `oauth`: the OAuth 2.1 authorization server (ADR-11), pairing consent (ADR-14), OAuth for services (ADR-13).

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .store import (  # noqa: F401
    Optional,
    json,
    now,
    sqlite3,
    time,
)


# Only digests reach these methods (`tinysesam/oauth.py` computes them with the pepper); the logic of what
# is allowed lives there, here only the reads and the writes that must happen in ONE transaction.

def oauth_add_client(self, client_id: str, name: str, redirect_uris: list, now: int, ip) -> None:
    self._exec("INSERT INTO oauth_client(client_id, name, redirect_uris, created_at, created_ip) "
               "VALUES (?, ?, ?, ?, ?)", (client_id, name, json.dumps(list(redirect_uris)), now, ip))


def oauth_client(self, client_id) -> Optional[dict]:
    r = self._one("SELECT * FROM oauth_client WHERE client_id=?", (str(client_id or ""),))
    if r is None:
        return None
    d = dict(r)
    d["redirect_uris"] = json.loads(d["redirect_uris"] or "[]")
    return d


def oauth_count_idle_clients(self) -> int:
    """Registrations that never led to a grant — the cap of open registration counts them (services do not
    register themselves and are not counted)."""
    r = self._one("SELECT COUNT(*) AS n FROM oauth_client c WHERE NOT EXISTS "
                  "(SELECT 1 FROM oauth_grant g WHERE g.client_id = c.client_id) AND NOT EXISTS "
                  "(SELECT 1 FROM oauth_service_client s WHERE s.client_id = c.client_id)")
    return int(r["n"]) if r else 0


def oauth_evict_idle_client(self, created_before: int) -> bool:
    """Delete the longest-unused registration without a grant (and not a service) that came into being before
    `created_before` — the cap of open registration makes room (A-4). True if one went."""
    return self._exec(
        "DELETE FROM oauth_client WHERE client_id = (SELECT c.client_id FROM oauth_client c WHERE c.created_at < ? "
        "AND NOT EXISTS (SELECT 1 FROM oauth_grant g WHERE g.client_id = c.client_id) AND NOT EXISTS "
        "(SELECT 1 FROM oauth_service_client s WHERE s.client_id = c.client_id) "
        "ORDER BY COALESCE(c.last_used, c.created_at), c.created_at LIMIT 1)", (int(created_before),)).rowcount == 1


def oauth_touch_client(self, client_id: str, now: int) -> None:
    self._exec("UPDATE oauth_client SET last_used=? WHERE client_id=?", (now, client_id))


def oauth_add_request(self, id_hash: str, browser_hash: str, client_id: str, params: dict,
                      expires_at: int) -> None:
    self._exec("INSERT INTO oauth_request(id_hash, browser_hash, client_id, params, expires_at) "
               "VALUES (?, ?, ?, ?, ?)", (id_hash, browser_hash, client_id, json.dumps(params), expires_at))


def oauth_request(self, id_hash: str, now: int) -> Optional[dict]:
    r = self._one("SELECT * FROM oauth_request WHERE id_hash=? AND expires_at > ?", (id_hash, now))
    if r is None:
        return None
    d = dict(r)
    d["params"] = json.loads(d["params"] or "{}")
    return d


def oauth_take_request(self, id_hash: str) -> bool:
    """Delete the request — True for exactly one caller (a consent is answered once)."""
    return self._exec("DELETE FROM oauth_request WHERE id_hash=?", (id_hash,)).rowcount == 1


def oauth_add_code(self, code_hash: str, client_id: str, user_id: int, redirect_uri: str,
                   code_challenge: str, resource: str, scope: str, now: int, expires_at: int,
                   consent_via: Optional[str] = None) -> None:
    self._exec("INSERT INTO oauth_code(code_hash, client_id, user_id, redirect_uri, code_challenge, resource, "
               "scope, created_at, expires_at, consent_via) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
               (code_hash, client_id, user_id, redirect_uri, code_challenge, resource, scope, now, expires_at,
                consent_via))


def oauth_replace_consent_pairing(self, code_hash: str, user_id: int, now: int, expires_at: int,
                                  payload: dict) -> None:
    """A new pairing code for `user_id` — and every open one of the account (issued or armed) goes, in the same
    transaction: an account has at most one pairing at a time, the latest it asked for."""
    with self._writing():
        self._begin_immediate()
        self.db.execute("DELETE FROM magic_token WHERE user_id=? AND used_at IS NULL AND purpose IN (?, ?)",
                        (int(user_id), self.CONSENT_PAIRING, self.CONSENT_ARMED))
        self.db.execute("INSERT INTO magic_token(token_hash, purpose, user_id, email, payload, created_at, "
                        "expires_at) VALUES (?, ?, ?, NULL, ?, ?, ?)",
                        (code_hash, self.CONSENT_PAIRING, int(user_id), json.dumps(payload), now, expires_at))
        self.db.commit()
        self._written = time.monotonic()


def oauth_arm_consent_pairing(self, code_hash: str, now: int) -> bool:
    """Redeem a pairing code: issued → armed, atomically. True for exactly one caller of an unused, unexpired
    code — a second redemption (or one racing the first) finds no issued row any more."""
    return self._exec("UPDATE magic_token SET purpose=? WHERE token_hash=? AND purpose=? AND used_at IS NULL "
                      "AND expires_at>=?", (self.CONSENT_ARMED, code_hash, self.CONSENT_PAIRING, now)).rowcount == 1


def oauth_armed_consent_pairing(self, user_id: int, now: int) -> Optional[sqlite3.Row]:
    """The armed, unused, unexpired pairing of the account — or None."""
    return self._one("SELECT * FROM magic_token WHERE user_id=? AND purpose=? AND used_at IS NULL "
                     "AND expires_at>=? ORDER BY created_at DESC LIMIT 1", (int(user_id), self.CONSENT_ARMED, now))


def oauth_use_consent_pairing(self, code_hash: str, now: int) -> bool:
    """Spend the armed consent — atomically: True for exactly one authorization, also across processes."""
    return self._exec("UPDATE magic_token SET used_at=? WHERE token_hash=? AND purpose=? AND used_at IS NULL "
                      "AND expires_at>=?", (now, code_hash, self.CONSENT_ARMED, now)).rowcount == 1


def oauth_release_consent_pairing(self, code_hash: str, used_at: int) -> None:
    """Give a spent consent back when the authorization it was spent on could not be answered after all."""
    self._exec("UPDATE magic_token SET used_at=NULL WHERE token_hash=? AND purpose=? AND used_at=?",
               (code_hash, self.CONSENT_ARMED, used_at))


def oauth_live_tokens_before(self, when: int, now: int) -> int:
    """Codes and tokens created up to `when` that are still valid — what a pepper retired at `when` would cut."""
    return int(self._one("SELECT (SELECT COUNT(*) FROM oauth_token t JOIN oauth_grant g ON g.id = t.grant_id "
                         "WHERE t.created_at <= ? AND t.expires_at > ? AND t.used_at IS NULL "
                         "AND g.revoked_at IS NULL) + (SELECT COUNT(*) FROM oauth_code WHERE created_at <= ? "
                         "AND expires_at > ? AND consumed_at IS NULL) AS n", (when, now, when, now))["n"])


def oauth_code(self, code_hash: str) -> Optional[sqlite3.Row]:
    return self._one("SELECT * FROM oauth_code WHERE code_hash=?", (code_hash,))


def oauth_consume_code(self, code_hash: str, now: int) -> bool:
    """Mark the code used — atomically: True for exactly one caller, also across processes."""
    return self._exec("UPDATE oauth_code SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL",
                      (now, code_hash)).rowcount == 1


def _oauth_insert_tokens(self, grant_id: int, tokens, now: int) -> None:
    """Insert `(digest, kind, scope, expires_at)` rows (without commit, under `_lock`)."""
    self.db.executemany(
        "INSERT INTO oauth_token(token_hash, grant_id, kind, scope, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?)", [(h, grant_id, kind, scope, now, exp) for h, kind, scope, exp in tokens])


def oauth_mark_code_reused(self, code_hash: str) -> Optional[int]:
    """A consumed code came back: the grant it produced (to revoke it) — or 0 if its first exchange has not written
    the grant yet. The 0 stays in `grant_id` as the reuse mark that `oauth_create_grant` reads in the same
    transaction as it writes the grant (A-6). None for an unknown code."""
    with self._writing():
        self._begin_immediate()
        self.db.execute("UPDATE oauth_code SET grant_id=0 WHERE code_hash=? AND grant_id IS NULL", (code_hash,))
        row = self.db.execute("SELECT grant_id FROM oauth_code WHERE code_hash=?", (code_hash,)).fetchone()
        self.db.commit()
        self._written = time.monotonic()
        return None if row is None else int(row[0])


def oauth_create_grant(self, code_hash: str, client_id: str, user_id: int, resource: str, scope: str,
                       now: int, ip, expires_at, tokens) -> Optional[int]:
    """Grant + first tokens + the code's link to the grant, in ONE transaction. Returns the grant ID — or None,
    and nothing is written, if the code came back while its first exchange ran (`oauth_mark_code_reused`; until
    attack round 2026-11-21, A-6, that second exchange found no grant to revoke and the first one's lived on)."""
    with self._writing():
        self._begin_immediate()
        mark = self.db.execute("SELECT grant_id FROM oauth_code WHERE code_hash=?", (code_hash,)).fetchone()
        if mark is not None and mark[0] is not None:
            self.db.rollback()
            return None
        # How the person allowed it travels from the code (ADR-14): the device list says "via pairing code".
        cur = self.db.execute(
            "INSERT INTO oauth_grant(client_id, user_id, resource, scope, created_at, created_ip, last_used, "
            "last_ip, expires_at, consent_via) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "(SELECT consent_via FROM oauth_code WHERE code_hash=?))",
            (client_id, user_id, resource, scope, now, ip, now, ip, expires_at, code_hash))
        grant_id = int(cur.lastrowid or 0)
        self._oauth_insert_tokens(grant_id, tokens, now)
        self.db.execute("UPDATE oauth_code SET grant_id=? WHERE code_hash=?", (grant_id, code_hash))
        self.db.execute("UPDATE oauth_client SET last_used=? WHERE client_id=?", (now, client_id))
        self.db.commit()
        self._written = time.monotonic()
        return grant_id


def oauth_token(self, token_hash: str) -> Optional[sqlite3.Row]:
    """The token row joined with its grant (`g_*` columns) and, for a service (T-60), its service row (`s_*`;
    `s_client_id` is NULL for a person's tool) — or None."""
    return self._one(
        "SELECT t.*, g.client_id AS g_client_id, g.user_id AS g_user_id, g.resource AS g_resource, "
        "g.scope AS g_scope, g.expires_at AS g_expires_at, g.revoked_at AS g_revoked_at, "
        "s.client_id AS s_client_id, s.user_id AS s_user_id, s.roles AS s_roles, s.resources AS s_resources, "
        "s.revoked_at AS s_revoked_at "
        "FROM oauth_token t JOIN oauth_grant g ON g.id = t.grant_id "
        "LEFT JOIN oauth_service_client s ON s.client_id = g.client_id WHERE t.token_hash=?", (token_hash,))


def oauth_rotate(self, old_hash: str, grant_id: int, now: int, ip, tokens, successor) -> bool:
    """Refresh rotation in ONE transaction: mark the old refresh token used (only if it was not yet — False
    otherwise, and nothing is written), drop the family's previous access tokens, insert the new pair,
    note use and address on the grant. `successor` (encrypted, grace window) or None."""
    with self._writing():
        cur = self.db.execute("UPDATE oauth_token SET used_at=?, successor=? WHERE token_hash=? "
                              "AND kind='refresh' AND used_at IS NULL", (now, successor, old_hash))
        if cur.rowcount != 1:
            self._discard()
            return False
        self.db.execute("DELETE FROM oauth_token WHERE grant_id=? AND kind='access'", (grant_id,))
        self._oauth_insert_tokens(grant_id, tokens, now)
        self.db.execute("UPDATE oauth_grant SET last_used=?, last_ip=? WHERE id=?", (now, ip, grant_id))
        self.db.commit()
        self._written = time.monotonic()
        return True


def oauth_drop_successor(self, token_hash: str) -> None:
    self._exec("UPDATE oauth_token SET successor=NULL WHERE token_hash=?", (token_hash,))


def seal_oauth_successor(self, token_hash: str, text: str) -> str:
    """The successor pair of a refresh token (grace window), encrypted and bound to that token's row."""
    return self._seal(text, "oauth_token.successor", token_hash)


def open_oauth_successor(self, row) -> Optional[str]:
    return self._open(row["successor"], "oauth_token.successor", row["token_hash"])


def oauth_touch_grant(self, grant_id: int, now: int, ip) -> None:
    self._exec("UPDATE oauth_grant SET last_used=?, last_ip=? WHERE id=?", (now, ip, grant_id))


def oauth_revoke_grant(self, grant_id: int, reason: str, now: int) -> bool:
    """Revoke a family: the grant is marked, its tokens are gone. True if it was live."""
    with self._writing():
        cur = self.db.execute("UPDATE oauth_grant SET revoked_at=?, revoked_reason=? WHERE id=? "
                              "AND revoked_at IS NULL", (now, reason, grant_id))
        self.db.execute("DELETE FROM oauth_token WHERE grant_id=?", (grant_id,))
        self.db.commit()
        self._written = time.monotonic()
        return cur.rowcount == 1


def oauth_grant(self, grant_id) -> Optional[sqlite3.Row]:
    return self._one("SELECT g.*, c.name AS client_name FROM oauth_grant g "
                     "LEFT JOIN oauth_client c ON c.client_id = g.client_id WHERE g.id=?", (grant_id,))


def oauth_grants(self, now: int, user_id=None, live_only: bool = True) -> list:
    """The connected devices (grants) — of one account or all; live = not revoked and a token not expired.
    Without the grants of services (T-60): those are listed per service (`oauth_service_clients`)."""
    where = ["NOT EXISTS (SELECT 1 FROM oauth_service_client s WHERE s.client_id = g.client_id)"]
    args: list = []
    if user_id is not None:
        where.append("g.user_id=?")
        args.append(int(user_id))
    if live_only:
        where.append("g.revoked_at IS NULL AND EXISTS (SELECT 1 FROM oauth_token t WHERE t.grant_id = g.id "
                     "AND t.expires_at > ? AND t.used_at IS NULL)")
        args.append(now)
    sql = ("SELECT g.*, c.name AS client_name, u.username FROM oauth_grant g "
           "LEFT JOIN oauth_client c ON c.client_id = g.client_id LEFT JOIN users u ON u.id = g.user_id"
           + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY g.created_at DESC, g.id DESC")
    return self._all(sql, tuple(args))


def oauth_user_grant_ids(self, user_id: int) -> list:
    return [int(r["id"]) for r in self._all("SELECT id FROM oauth_grant WHERE user_id=? AND revoked_at IS NULL",
                                            (int(user_id),))]


def gc_oauth(self, now: int, idle_client_sec: int, revoked_keep_sec: int) -> dict:
    """Expired requests, codes, tokens; grants without a live token or revoked long ago; registrations that
    never led to a grant (or whose grants are all gone) — DCR is open, every logout or port collision of a
    client registers anew."""
    with self._writing():
        n = {"oauth_requests": self.db.execute("DELETE FROM oauth_request WHERE expires_at <= ?",
                                               (now,)).rowcount,
             # A consumed code stays until its deadline plus an hour: a second exchange inside that window
             # still finds the grant to revoke (reuse).
             "oauth_codes": self.db.execute("DELETE FROM oauth_code WHERE expires_at <= ?",
                                            (now - 3600,)).rowcount,
             "oauth_tokens": self.db.execute("DELETE FROM oauth_token WHERE expires_at <= ?", (now,)).rowcount}
        n["oauth_grants"] = self.db.execute(
            "DELETE FROM oauth_grant WHERE (revoked_at IS NOT NULL AND revoked_at <= ?) OR "
            "(revoked_at IS NULL AND NOT EXISTS (SELECT 1 FROM oauth_token t WHERE t.grant_id = oauth_grant.id))",
            (now - revoked_keep_sec,)).rowcount
        n["oauth_clients"] = self.db.execute(
            "DELETE FROM oauth_client WHERE created_at <= ? AND COALESCE(last_used, created_at) <= ? AND NOT EXISTS "
            "(SELECT 1 FROM oauth_grant g WHERE g.client_id = oauth_client.client_id) AND NOT EXISTS "
            "(SELECT 1 FROM oauth_service_client s WHERE s.client_id = oauth_client.client_id "
            "AND (s.revoked_at IS NULL OR s.revoked_at > ?))",
            (now - idle_client_sec, now - idle_client_sec, now - revoked_keep_sec)).rowcount
        # Services (T-60): replay entries past their deadline and keys past their rotation overlap. An expired
        # key stays — the lists say "expired" instead of showing a service without a key.
        n["oauth_assertions"] = self.db.execute("DELETE FROM oauth_assertion WHERE expires_at <= ?",
                                                (now,)).rowcount
        n["oauth_client_keys"] = self.db.execute(
            "DELETE FROM oauth_client_key WHERE retire_at IS NOT NULL AND retire_at <= ?", (now,)).rowcount
        self.db.commit()
        self._written = time.monotonic()
        return n


# The rules live in `tinysesam/oauth_services.py`; here the reads and the writes that must be ONE transaction.

def oauth_pair_service(self, code_hash: str, now: int, client_id: str, name: str, user_id: int, roles,
                       resources: list, created_by, ip, key: dict) -> bool:
    """Redeem a pairing code and create the service with its first key — in ONE transaction. False (nothing
    written) if the code was not an unused, unexpired pairing code for `user_id` any more."""
    with self._writing():
        cur = self.db.execute(
            "UPDATE magic_token SET used_at=? WHERE token_hash=? AND purpose='oauth_pairing' AND user_id=? "
            "AND used_at IS NULL AND expires_at>=?", (now, code_hash, int(user_id), now))
        if cur.rowcount != 1:
            self._discard()
            return False
        self.db.execute("INSERT INTO oauth_client(client_id, name, redirect_uris, created_at, created_ip) "
                        "VALUES (?, ?, '[]', ?, ?)", (client_id, name, now, ip))
        self.db.execute("INSERT INTO oauth_service_client(client_id, user_id, roles, resources, created_by, "
                        "last_ip) VALUES (?, ?, ?, ?, ?, ?)",
                        (client_id, int(user_id), json.dumps(roles) if roles is not None else None,
                         json.dumps(list(resources)), created_by, ip))
        self._oauth_insert_key(client_id, key, now, ip)
        self.db.commit()
        self._written = time.monotonic()
        return True


def _oauth_insert_key(self, client_id: str, key: dict, now: int, ip) -> None:
    self.db.execute("INSERT INTO oauth_client_key(client_id, kid, jwk, created_at, created_ip, expires_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (client_id, key["kid"], json.dumps(key["jwk"], sort_keys=True), now, ip, key["expires_at"]))


def oauth_service(self, client_id) -> Optional[dict]:
    """A service with its account name — or None (also for a person's tool)."""
    r = self._one("SELECT s.*, c.name, c.created_at, c.created_ip, c.last_used, u.username "
                  "FROM oauth_service_client s JOIN oauth_client c ON c.client_id = s.client_id "
                  "LEFT JOIN users u ON u.id = s.user_id WHERE s.client_id=?", (str(client_id or ""),))
    return self._service_dict(r) if r is not None else None


def oauth_services(self, user_id=None, include_revoked: bool = False) -> list:
    where, args = [], []
    if user_id is not None:
        where.append("s.user_id=?")
        args.append(int(user_id))
    if not include_revoked:
        where.append("s.revoked_at IS NULL")
    rows = self._all("SELECT s.*, c.name, c.created_at, c.created_ip, c.last_used, u.username "
                     "FROM oauth_service_client s JOIN oauth_client c ON c.client_id = s.client_id "
                     "LEFT JOIN users u ON u.id = s.user_id" + (" WHERE " + " AND ".join(where) if where else "")
                     + " ORDER BY c.created_at DESC, s.client_id", tuple(args))
    return [self._service_dict(r) for r in rows]


def oauth_service_ids(self, user_id: int) -> list:
    return [r["client_id"] for r in self._all("SELECT client_id FROM oauth_service_client WHERE user_id=? "
                                              "AND revoked_at IS NULL", (int(user_id),))]


def oauth_client_keys(self, client_id: str) -> list:
    """All stored keys of a service, the current one first (`retire_at` NULL), then by age."""
    rows = self._all("SELECT * FROM oauth_client_key WHERE client_id=? "
                     "ORDER BY retire_at IS NOT NULL, created_at DESC, kid", (str(client_id),))
    out = []
    for r in rows:
        d = dict(r)
        d["jwk"] = json.loads(d["jwk"])
        out.append(d)
    return out


def oauth_note_assertion(self, client_id: str, jti: str, expires_at: int) -> bool:
    """Remember a client assertion's `jti` until its deadline — True only the FIRST time (replay protection,
    atomic across processes by the primary key)."""
    return self._exec("INSERT OR IGNORE INTO oauth_assertion(client_id, jti, expires_at) VALUES (?, ?, ?)",
                      (client_id, jti, int(expires_at))).rowcount == 1


def oauth_add_client_key(self, client_id: str, key: dict, now: int, ip, retire_at: int) -> bool:
    """A new current key; every other key of the service is accepted only until `retire_at` from now on. False
    if the service is revoked."""
    with self._writing():
        live = self.db.execute("SELECT 1 FROM oauth_service_client WHERE client_id=? AND revoked_at IS NULL",
                               (client_id,)).fetchone()
        if live is None:
            self._discard()
            return False
        self.db.execute("UPDATE oauth_client_key SET retire_at=? WHERE client_id=? "
                        "AND (retire_at IS NULL OR retire_at > ?)", (retire_at, client_id, retire_at))
        self._oauth_insert_key(client_id, key, now, ip)
        self.db.commit()
        self._written = time.monotonic()
        return True


def oauth_service_token(self, client_id: str, user_id: int, resource: str, scope: str, now: int, ip,
                        kid: str, token: tuple) -> int:
    """Issue one access token to a service: the grant of (service, resource) is reused or created, the token
    row inserted, use and address noted on grant, service and key — ONE transaction. Returns the grant ID."""
    with self._writing():
        r = self.db.execute("SELECT id FROM oauth_grant WHERE client_id=? AND user_id=? AND resource=? "
                            "AND revoked_at IS NULL ORDER BY id DESC LIMIT 1",
                            (client_id, int(user_id), resource)).fetchone()
        if r is None:
            cur = self.db.execute(
                "INSERT INTO oauth_grant(client_id, user_id, resource, scope, created_at, created_ip, last_used, "
                "last_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (client_id, int(user_id), resource, scope, now, ip, now, ip))
            grant_id = int(cur.lastrowid or 0)
        else:
            grant_id = int(r["id"])
            self.db.execute("UPDATE oauth_grant SET last_used=?, last_ip=? WHERE id=?", (now, ip, grant_id))
        self._oauth_insert_tokens(grant_id, [token], now)
        self.db.execute("UPDATE oauth_client SET last_used=? WHERE client_id=?", (now, client_id))
        self.db.execute("UPDATE oauth_service_client SET last_ip=? WHERE client_id=?", (ip, client_id))
        self.db.execute("UPDATE oauth_client_key SET last_used=? WHERE client_id=? AND kid=?",
                        (now, client_id, kid))
        self.db.commit()
        self._written = time.monotonic()
        return grant_id


def oauth_revoke_service(self, client_id: str, reason: str, now: int) -> bool:
    """Revoke a service: marked, its keys gone, its grants revoked and their tokens deleted — at once. True if
    it was live."""
    with self._writing():
        cur = self.db.execute("UPDATE oauth_service_client SET revoked_at=?, revoked_reason=? WHERE client_id=? "
                              "AND revoked_at IS NULL", (now, reason, client_id))
        self.db.execute("DELETE FROM oauth_client_key WHERE client_id=?", (client_id,))
        self.db.execute("UPDATE oauth_grant SET revoked_at=?, revoked_reason=? WHERE client_id=? "
                        "AND revoked_at IS NULL", (now, reason, client_id))
        self.db.execute("DELETE FROM oauth_token WHERE grant_id IN "
                        "(SELECT id FROM oauth_grant WHERE client_id=?)", (client_id,))
        self.db.commit()
        self._written = time.monotonic()
        return cur.rowcount == 1


def revoke_user_access(self, user_id: int, reason: str) -> dict:
    """Revoke every standing credential of an account at the store level — for the offline CLI (`tinysesam
    passwd`), which has no `TinySesam` and therefore no hook. The online paths go through
    `TinySesam._keys_revoked`, which does the same per kind and notifies the owner. Returns the counts."""
    uid, now = int(user_id), _store._now()
    services = sum(1 for cid in self.oauth_service_ids(uid) if self.oauth_revoke_service(cid, reason, now))
    return {"api_keys": self.revoke_user_api_keys(uid),
            "app_passwords": self.app_passwords_revoke_all(uid, reason),
            "services": services,
            "oauth_devices": sum(1 for gid in self.oauth_user_grant_ids(uid)
                                 if self.oauth_revoke_grant(gid, reason, now))}

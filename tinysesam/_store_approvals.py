"""The store part `approvals`: approvals of application actions (schema 22).

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""



def add_approval(self, row: dict) -> None:
    """Insert a new approval row (all columns named in `row`)."""
    cols = ", ".join(row)
    marks = ", ".join("?" for _ in row)
    self._exec(f"INSERT INTO approval({cols}) VALUES ({marks})", tuple(row.values()))


def get_approval(self, approval_id: str):
    return self._one("SELECT * FROM approval WHERE id=?", (str(approval_id),))


def approval_transition(self, approval_id: str, old: str, new: str, **fields) -> bool:
    """Move an approval from `old` to `new` — atomically: `UPDATE … WHERE state = old`. True only for the ONE
    caller whose update changed the row; a second, parallel caller gets False and must not act."""
    sets = ", ".join(["state=?"] + [f"{k}=?" for k in fields])
    args = (new, *fields.values(), str(approval_id), old)
    return self._exec(f"UPDATE approval SET {sets} WHERE id=? AND state=?", args).rowcount == 1


def set_approval_fields(self, approval_id: str, state: str, **fields) -> bool:
    """Set result columns of an approval that is (still) in `state` — no state change."""
    sets = ", ".join(f"{k}=?" for k in fields)
    return self._exec(f"UPDATE approval SET {sets} WHERE id=? AND state=?",
                      (*fields.values(), str(approval_id), state)).rowcount == 1


def list_approvals_pending(self, subject_id: int, now: int) -> list:
    """The open, unexpired approvals an account has to decide — newest first."""
    return self._all("SELECT * FROM approval WHERE subject_id=? AND state='pending' AND expires_at>=? "
                     "ORDER BY created_at DESC", (int(subject_id), int(now)))


def count_approvals_pending(self, subject_id: int, now: int) -> int:
    r = self._one("SELECT COUNT(*) AS n FROM approval WHERE subject_id=? AND state='pending' AND expires_at>=?",
                  (int(subject_id), int(now)))
    return int(r["n"]) if r else 0


def count_approvals_open_by(self, requester_kind: str, requester_ref: str, now: int) -> int:
    r = self._one("SELECT COUNT(*) AS n FROM approval WHERE requester_kind=? AND requester_ref=? "
                  "AND state='pending' AND expires_at>=?", (requester_kind, str(requester_ref), int(now)))
    return int(r["n"]) if r else 0


def count_approvals_since(self, subject_id: int, since: int) -> int:
    """How many approvals were requested for an account since `since` (every state counts)."""
    r = self._one("SELECT COUNT(*) AS n FROM approval WHERE subject_id=? AND created_at>=?",
                  (int(subject_id), int(since)))
    return int(r["n"]) if r else 0


def approval_rejections(self, requester_kind: str, requester_ref: str, type_: str, since: int) -> list:
    """The decision times of the rejections of one type from one requester since `since`, oldest first."""
    return [int(r["decided_at"]) for r in self._all(
        "SELECT decided_at FROM approval WHERE requester_kind=? AND requester_ref=? AND type=? "
        "AND state='rejected' AND decided_at>=? ORDER BY decided_at", (requester_kind, str(requester_ref),
                                                                        type_, int(since)))]


def gc_approvals(self, now: int, keep_until: int) -> tuple[list, int]:
    """Expire open approvals past their deadline (returns their rows, for the audit) and delete closed rows
    decided (or created) before `keep_until`. One transaction, so a row is never expired twice."""
    with self._writing():
        stale = self.db.execute("SELECT id, type, subject_id, requester_kind, requester_ref, payload_hash "
                                "FROM approval WHERE state IN ('pending','approved') AND expires_at<?",
                                (int(now),)).fetchall()
        self.db.execute("UPDATE approval SET state='expired', decided_at=? "
                        "WHERE state IN ('pending','approved') AND expires_at<?", (int(now), int(now)))
        away = self.db.execute("DELETE FROM approval WHERE state NOT IN ('pending','approved') "
                               "AND COALESCE(decided_at, created_at)<?", (int(keep_until),)).rowcount
        self.db.commit()
    return list(stale), int(away)

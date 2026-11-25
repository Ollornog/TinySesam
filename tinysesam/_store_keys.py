"""The store part `keys`: the vault context and re-encryption, keys of their own purpose in the database (ADR-12).

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .store import (  # noqa: F401
    _KID_LEN,
    base64,
)


# ---------- the vault: context, re-encryption (T-48, T-54) ----------
def _seal(self, plaintext: str, column: str, *parts) -> str:
    from .vault import context
    return self.vault.encrypt(plaintext, context(column, *parts))


def _open(self, value, column: str, *parts):
    """Decrypt a stored value — `v2:` only (A-5)."""
    from .vault import context
    return self.vault.decrypt(value, context(column, *parts))


def reencrypt(self, *, limit: int = 0, progress=None) -> dict:
    """Rewrite stored secrets with the ACTIVE key and their context — after `keys rotate`. Compare-and-swap per
    row: a value the service changed meanwhile stays. `progress(column, done, total)`. Returns {column:
    rewritten}."""
    out = {}
    for column, select in self.ENCRYPTED:
        table, col = column.split(".")
        rows = [r for r in self._all(select)
                if r["value"] is not None and str(r["value"]).startswith("v2:")
                and self.vault.needs_rewrite(r["value"])]
        if limit:
            rows = rows[:limit]
        done = 0
        for r in rows:
            parts = [r[k] for k in r.keys() if k not in ("rid", "value")]
            plain = self._open(r["value"], column, *parts)
            new = self._seal(plain, column, *parts)
            done += self._exec(f"UPDATE {table} SET {col}=? WHERE rowid=? AND {col}=?",
                               (new, r["rid"], r["value"])).rowcount
            if progress is not None:
                progress(column, done, len(rows))
        out[column] = done
    return out


def ciphertext_counts(self) -> dict:
    """{kid: number of stored values} over every encrypted column — what still needs which key."""
    out: dict = {}
    for column, _select in self.ENCRYPTED:
        table, col = column.split(".")
        for kid, n in self._all(f"SELECT substr({col}, 4, {_KID_LEN}), COUNT(*) FROM {table} "
                                f"WHERE {col} LIKE 'v2:%' GROUP BY 1"):
            out[kid] = out.get(kid, 0) + int(n)
    return out


# ---------- keys of their own purpose in the database (T-48, ADR-12) ----------
def key_ring_rows(self, purpose: str) -> list:
    """The keys of `purpose` from `key_material`, decrypted — the active one first, then the newest previous."""
    from . import keys as _keys
    out = []
    for r in self._all("SELECT kid, material, since, note FROM key_material WHERE purpose=? "
                       "ORDER BY since IS NOT NULL, since DESC, created_at DESC", (purpose,)):
        raw = base64.b64decode(self._open(r["material"], "key_material.material", purpose, r["kid"]))
        if _keys.kid_for(purpose, raw) != r["kid"]:
            raise ValueError(f"key_material: the {purpose} key {r['kid']} does not match its ID")
        out.append(_keys.Key(r["kid"], raw, r["since"], r["note"] or ""))
    if out and out[0].since is not None:
        raise ValueError(f"key_material: no active {purpose} key")
    return out


def _key_insert(self, purpose: str, material: bytes, since, note: str = "") -> str:
    from . import keys as _keys
    kid = _keys.kid_for(purpose, material)
    self.db.execute("INSERT INTO key_material(purpose, kid, material, created_at, since, note) "
                    "VALUES (?,?,?,?,?,?)",
                    (purpose, kid, self._seal(base64.b64encode(material).decode("ascii"),
                                              "key_material.material", purpose, kid), _store._now(), since, note))
    return kid


def key_ring_create(self, purpose: str, material: bytes) -> bool:
    """The first keyring of `purpose` — only if there is none yet (several workers starting at once: one
    creates it, the others read it)."""
    if self.vault is None:
        raise RuntimeError("Keys are only stored encrypted (vault.Vault).")
    with self._writing():
        self._begin_immediate()
        if self.db.execute("SELECT 1 FROM key_material WHERE purpose=? LIMIT 1", (purpose,)).fetchone():
            self.db.rollback()
            return False
        self._key_insert(purpose, material, None)
        self.db.commit()
    return True


def key_ring_rotate(self, purpose: str, material: bytes) -> str:
    """A new active key; the active one becomes previous (since now). Returns the new key ID."""
    with self._writing():
        self._begin_immediate()
        self.db.execute("UPDATE key_material SET since=? WHERE purpose=? AND since IS NULL", (_store._now(), purpose))
        kid = self._key_insert(purpose, material, None)
        self.db.commit()
    return kid


def key_ring_retire(self, purpose: str, kids) -> int:
    """Remove previous keys — never the active one."""
    kids = list(kids)
    if not kids:
        return 0
    return self._exec(f"DELETE FROM key_material WHERE purpose=? AND since IS NOT NULL "
                      f"AND kid IN ({','.join('?' * len(kids))})", (purpose, *kids)).rowcount

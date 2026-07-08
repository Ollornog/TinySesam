"""E1: Multi-Worker-Rate-Limit — RedisRateLimiter (Fake-Client), Fallback, eigenes Backend."""
import tempfile, os
from tinysesam import TinySesam, TinySesamConfig
from tinysesam import security


def ok(name):
    print(f"  ✓ {name}")


# ---------- RedisRateLimiter mit gefälschtem Client (kein Server/redis nötig) ----------
class FakePipe:
    def __init__(self, store):
        self.store = store
        self._k = None

    def incr(self, k):
        self._k = k
        return self

    def expire(self, k, t):
        return self

    def execute(self):
        self.store[self._k] = self.store.get(self._k, 0) + 1
        return [self.store[self._k]]


class FakeRedis:
    def __init__(self, broken=False):
        self.store = {}
        self.broken = broken

    def pipeline(self):
        if self.broken:
            raise RuntimeError("redis down")
        return FakePipe(self.store)


rl = object.__new__(security.RedisRateLimiter)   # __init__ umgehen (kein echtes redis)
rl.client = FakeRedis()
rl.prefix = "tsrl"
results = [rl.allow("1.2.3.4", 3, 60) for _ in range(4)]
assert results == [True, True, True, False], results
assert rl.allow("5.6.7.8", 3, 60) is True   # anderer Key eigener Zähler
ok("RedisRateLimiter: Fixed-Window zählt korrekt (3 erlaubt, 4. blockiert)")

# fail-open bei Redis-Fehler
rl.client = FakeRedis(broken=True)
assert rl.allow("x", 1, 60) is True
ok("RedisRateLimiter: Redis-Fehler → fail-open (erlauben)")

# ---------- redis_url gesetzt, aber redis nicht installiert → In-Memory-Fallback, kein Crash ----------
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, redis_url="redis://localhost:6379/0", cookie_secure=False))
assert isinstance(auth.rl, security.RateLimiter)
ok("redis_url ohne redis-Paket → In-Memory-Fallback (kein Crash)")

# ---------- eigenes Backend injizieren ----------
class CountingLimiter:
    def __init__(self): self.calls = 0
    def allow(self, key, mx, win): self.calls += 1; return self.calls <= 2

auth.set_rate_limiter(CountingLimiter())
assert auth.rate_ok("ip") and auth.rate_ok("ip") and not auth.rate_ok("ip")
ok("set_rate_limiter: eigenes Backend wird genutzt")
os.remove(db)

print("\nRATE-LIMIT OK ✅")

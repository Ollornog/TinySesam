"""E1: Multi-Worker-Rate-Limit — RedisRateLimiter (Fake-Client), Fallback, eigenes Backend."""
import os
import tempfile, os
from tinysesam import TinySesam, TinySesamConfig
from tinysesam import security


def ok(name):
    print(f"  ✓ {name}")


# ---------- RedisRateLimiter with a faked client (no server/redis needed) ----------
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


import importlib.util                                                            # noqa: E402
rl = object.__new__(security.RedisRateLimiter)   # bypass __init__ (no real redis)
rl.client = FakeRedis()
rl.prefix = "tsrl"
results = [rl.allow("1.2.3.4", 3, 60) for _ in range(4)]
assert results == [True, True, True, False], results
assert rl.allow("5.6.7.8", 3, 60) is True   # another key has its own counter
ok("RedisRateLimiter: fixed window counts correctly (3 allowed, 4th blocked)")

# ---------- B6-1 / B6-2: Redis fails → keep counting per process, and audibly ----------
# Until T-13 a Redis error meant “allow” — magic link, forgot password, registration and
# the federation start depend solely on this limit, so they were then open. And every
# request wrote a warning line, without anyone having asked at startup whether Redis is there.
# (Mutation probe: `return True` again in the `except` of `allow` → the second promise falls.)
import logging                                                                  # noqa: E402


class _Recording(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, rec):
        self.lines.append(rec.getMessage())


with_ = _Recording()
security.seclog.addHandler(with_)
try:
    rl.client = FakeRedis(broken=True)
    responses = [rl.allow("x", 3, 60) for _ in range(5)]
    assert responses == [True, True, True, False, False], \
        f"B6-1: without Redis the throttle stays open: {responses}"
    ok("B6-1: Redis outage → in-memory fallback keeps counting (3 allowed, then 429), nobody locked out")
    # Without a pause every request asks Redis again and fails again — still only the
    # change is reported. (The pause alone would otherwise merely hide the lines.)
    rl.pause_sec = 0.0
    rl._pause_until = 0.0
    for _ in range(50):
        rl.allow("y", 1000, 60)
    failure = [z for z in with_.lines if "unreachable" in z]
    assert len(failure) == 1, f"B6-2: {len(failure)} warning lines for 55 requests during the outage"
    # Redis is back: after the pause it is asked again, and the change is reported once.
    rl.client = FakeRedis()
    rl._pause_until = 0.0
    assert rl.allow("z", 3, 60) is True
    assert rl.allow("z", 3, 60) is True
    back = [z for z in with_.lines if "reachable again" in z]
    assert len(back) == 1, f"B6-2: the return is reported {len(back)} times"
    assert rl.client.store, "after the return Redis counts again"
    ok("B6-2: outage and return ONE line each, not one per request")

    # The constructor asks Redis at startup (ping), instead of letting the first visitor notice.
    if importlib.util.find_spec("redis"):
        with_.lines.clear()
        dead = security.RedisRateLimiter("redis://127.0.0.1:1/0")   # Port 1: dort lauscht nichts
        assert any("unreachable" in z for z in with_.lines), \
            "B6-2: an unreachable Redis is not noticed at startup"
        assert dead.allow("a", 1, 60) is True and dead.allow("a", 1, 60) is False, \
            "B6-1: the outage detected at startup does not throttle"
        ok("B6-2: unreachable Redis is already reported and throttled at build time")
finally:
    security.seclog.removeHandler(with_)

# ---------- R7-5: the in-memory limiter does not grow without bound ----------
# Every new address created a key, and none ever disappeared. Whoever changes the source address
# (an IPv6 /64 has enough of them) filled the memory. Now a cap applies, and
# the key dormant longest is evicted — never the one currently being throttled.
# (Mutation probe: remove the `popitem` loop in `RateLimiter.allow` → red.)
small = security.RateLimiter(max_keys=100)
assert small.allow("laut", 2, 60) and small.allow("laut", 2, 60) and not small.allow("laut", 2, 60)
for i in range(1000):
    small.allow(f"2001:db8::{i:x}", 5, 60)
    small.allow("laut", 2, 60)                    # the throttled one keeps asking
assert len(small) <= 100, f"R7-5: {len(small)} keys despite cap 100"
assert small.allow("laut", 2, 60) is False, "the one just throttled was evicted and is free again"
assert security.RateLimiter().max_keys > 0
ok("R7-5: number of keys capped; the throttled one stays throttled")

# ---------- redis_url set: with redis package → RedisRateLimiter, without → in-memory fallback ----------
# (no crash in either case; without a running Redis → in-memory fallback, the first call goes through)
# Port 1 instead of 6379, as above: on a machine with a real Redis the probe otherwise hit THAT one —
# it wrote counters into a foreign database, shared them with every simultaneous run and did not check
# the fallback at all that it announces.
import importlib.util
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, redis_url="redis://127.0.0.1:1/0", cookie_secure=False))
if importlib.util.find_spec("redis"):
    assert isinstance(auth.rl, security.RedisRateLimiter)
    assert auth.rl._disturbed, "no fallback — the probe reached a real Redis"
    assert auth._rate_ok("ip") is True   # Redis down → fallback, the first call goes through
    ok("redis_url + redis package → RedisRateLimiter (Redis down → in-memory fallback)")
else:
    assert isinstance(auth.rl, security.RateLimiter)
    ok("redis_url without redis package → in-memory fallback (no crash)")

# ---------- eigenes Backend injizieren ----------
class CountingLimiter:
    def __init__(self): self.calls = 0
    def allow(self, key, mx, win): self.calls += 1; return self.calls <= 2

auth.set_rate_limiter(CountingLimiter())
assert auth._rate_ok("ip") and auth._rate_ok("ip") and not auth._rate_ok("ip")
ok("set_rate_limiter: own backend is used")
os.remove(db)

print("\nRATE-LIMIT OK ✅")

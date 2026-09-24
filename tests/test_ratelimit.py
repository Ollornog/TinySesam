"""E1: Multi-Worker-Rate-Limit — RedisRateLimiter (Fake-Client), Fallback, eigenes Backend."""
import os
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


import importlib.util                                                            # noqa: E402
rl = object.__new__(security.RedisRateLimiter)   # __init__ umgehen (kein echtes redis)
rl.client = FakeRedis()
rl.prefix = "tsrl"
results = [rl.allow("1.2.3.4", 3, 60) for _ in range(4)]
assert results == [True, True, True, False], results
assert rl.allow("5.6.7.8", 3, 60) is True   # anderer Key eigener Zähler
ok("RedisRateLimiter: Fixed-Window zählt korrekt (3 erlaubt, 4. blockiert)")

# ---------- B6-1 / B6-2: Redis fällt aus → je Prozess weiterzählen, und zwar hörbar ----------
# Bis T-13 hiess ein Redis-Fehler „erlauben" — Magic-Link, Passwort vergessen, Registrierung und
# der Föderationsstart hängen aber allein an diesem Limit, sie waren dann offen. Und jede
# Anfrage schrieb eine Warnzeile, ohne dass beim Start je jemand gefragt hätte, ob Redis da ist.
# (Mutationsprobe: im `except` von `allow` wieder `return True` → die zweite Zusage fällt.)
import logging                                                                  # noqa: E402


class _Mitschnitt(logging.Handler):
    def __init__(self):
        super().__init__()
        self.zeilen = []

    def emit(self, rec):
        self.zeilen.append(rec.getMessage())


mit = _Mitschnitt()
security.seclog.addHandler(mit)
try:
    rl.client = FakeRedis(broken=True)
    antworten = [rl.allow("x", 3, 60) for _ in range(5)]
    assert antworten == [True, True, True, False, False], \
        f"B6-1: ohne Redis bleibt die Drossel offen: {antworten}"
    ok("B6-1: Redis-Ausfall → In-Memory-Rückfall zählt weiter (3 erlaubt, dann 429), niemand ausgesperrt")
    # Ohne Pause fragt jede Anfrage Redis erneut und scheitert erneut — gemeldet wird trotzdem
    # nur der Wechsel. (Die Pause allein würde die Zeilen sonst bloss verdecken.)
    rl.pause_sec = 0.0
    rl._pause_bis = 0.0
    for _ in range(50):
        rl.allow("y", 1000, 60)
    ausfall = [z for z in mit.zeilen if "nicht erreichbar" in z]
    assert len(ausfall) == 1, f"B6-2: {len(ausfall)} Warnzeilen für 55 Anfragen im Ausfall"
    # Redis ist zurück: nach der Pause wird wieder gefragt, und der Wechsel wird einmal gemeldet.
    rl.client = FakeRedis()
    rl._pause_bis = 0.0
    assert rl.allow("z", 3, 60) is True
    assert rl.allow("z", 3, 60) is True
    zurueck = [z for z in mit.zeilen if "wieder erreichbar" in z]
    assert len(zurueck) == 1, f"B6-2: die Rückkehr wird {len(zurueck)}-mal gemeldet"
    assert rl.client.store, "nach der Rückkehr zählt wieder Redis"
    ok("B6-2: Ausfall und Rückkehr je EINE Zeile, nicht eine je Anfrage")

    # Der Konstruktor fragt Redis beim Start (ping), statt es den ersten Besucher merken zu lassen.
    if importlib.util.find_spec("redis"):
        mit.zeilen.clear()
        tot = security.RedisRateLimiter("redis://127.0.0.1:1/0")   # Port 1: dort lauscht nichts
        assert any("nicht erreichbar" in z for z in mit.zeilen), \
            "B6-2: ein unerreichbares Redis fällt beim Start nicht auf"
        assert tot.allow("a", 1, 60) is True and tot.allow("a", 1, 60) is False, \
            "B6-1: der beim Start erkannte Ausfall drosselt nicht"
        ok("B6-2: unerreichbares Redis wird schon beim Aufbau gemeldet und gedrosselt")
finally:
    security.seclog.removeHandler(mit)

# ---------- R7-5: Der In-Memory-Limiter wächst nicht unbegrenzt ----------
# Jede neue Adresse legte einen Schlüssel an, und keiner verschwand je. Wer die Quelladresse
# wechselt (ein IPv6-/64 hat davon genug), füllte den Speicher. Jetzt gilt ein Deckel, und
# verdrängt wird der am längsten ruhende Schlüssel — nie der, der gerade gebremst wird.
# (Mutationsprobe: die `popitem`-Schleife in `RateLimiter.allow` streichen → rot.)
klein = security.RateLimiter(max_keys=100)
assert klein.allow("laut", 2, 60) and klein.allow("laut", 2, 60) and not klein.allow("laut", 2, 60)
for i in range(1000):
    klein.allow(f"2001:db8::{i:x}", 5, 60)
    klein.allow("laut", 2, 60)                    # der Gebremste fragt weiter
assert len(klein) <= 100, f"R7-5: {len(klein)} Schlüssel trotz Deckel 100"
assert klein.allow("laut", 2, 60) is False, "der gerade Gebremste wurde verdrängt und ist wieder frei"
assert security.RateLimiter().max_keys > 0
ok("R7-5: Schlüsselzahl gedeckelt; der Gebremste bleibt gebremst")

# ---------- redis_url gesetzt: mit redis-Paket → RedisRateLimiter, ohne → In-Memory-Fallback ----------
# (kein Crash in beiden Fällen; ohne laufenden Redis → In-Memory-Rückfall, der erste Aufruf geht durch)
import importlib.util
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, redis_url="redis://localhost:6379/0", cookie_secure=False))
if importlib.util.find_spec("redis"):
    assert isinstance(auth.rl, security.RedisRateLimiter)
    assert auth.rate_ok("ip") is True   # Redis down → Rückfall, der erste Aufruf geht durch
    ok("redis_url + redis-Paket → RedisRateLimiter (Redis down → In-Memory-Rückfall)")
else:
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

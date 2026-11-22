"""Orderly shutdown: `TinySesam.close()`, `lifespan`, `Store.close()` and `Outbox.close()` (T-67, origin B-13).

The background outboxes write to the store's single `sqlite3` connection from worker threads. Closing that
connection under a running job crashed the process (segmentation fault) or failed the job. `close()` refuses new
jobs, lets the queued ones finish and only then closes the database under the store lock.

The race runs in a SUBPROCESS started directly (not through `tests/_starter.py`, whose `_DrainingConnection` would
make even a raw `db.close()` wait): a crash there must not take this suite with it, and it shows the hazard as it
is in an embedding app. The raw variant (`auth.store.db.close()` under the running job) is the self-probe — the
scenario must be able to fail.
"""
import asyncio
import logging
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, gateway
from tinysesam.mailer import Outbox

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ok(name):
    print(f"  ✓ {name}")


def make(**kw):
    return TinySesam(TinySesamConfig(csrf_enabled=False, passkey_enabled=False,
                                     db_path=os.path.join(tempfile.mkdtemp(), "t.db"), **kw))


# ---------- the race: close under a running background job ----------
RACE = r"""
import os, sys, tempfile, threading, time
sys.path.insert(0, sys.argv[2])
from tinysesam import TinySesam, TinySesamConfig
auth = TinySesam(TinySesamConfig(passkey_enabled=False, db_path=os.path.join(tempfile.mkdtemp(), "r.db")))
started, stop, done = threading.Event(), threading.Event(), []

# The job writes on the shared connection until it is told to stop — not a fixed number of writes. Until 2026-11-22
# it wrote 400 rows, and under load (two CPUs, a dozen suites) those took longer than close()'s 10 s deadline:
# close() then correctly kept the database open (False), and the test read that as a failure. Now the job is inside
# its write loop when close() is called (started + one write), and it ends right after close() has begun to wait.
def job():
    i = 0
    while not stop.is_set():
        auth.audit("close_race", "probe", detail=str(i))
        i += 1
        started.set()
    auth.audit("close_race", "probe", detail="last")
    done.append(i)

queued = auth._notice_outcome.enqueue(job)
assert queued
assert started.wait(60), "the job never wrote"
if sys.argv[1] == "raw":
    auth.store.db.close()           # what the suites did before T-67 — under the running write loop
    stop.set()
    closed = True
    auth._notice_outcome.wait()
else:
    def release():                  # the moment close() refuses new jobs it is waiting for this one
        while not auth._notice_outcome.closed:
            time.sleep(0.001)
        stop.set()
    threading.Thread(target=release, daemon=True).start()
    closed = auth.close()
print(f"closed={closed} job_done={bool(done)}")
"""


def race(mode):
    r = subprocess.run([sys.executable, "-c", RACE, mode, ROOT], capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout.strip(), r.stderr


code, out, err = race("raw")
assert not (code == 0 and out == "closed=True job_done=True"), (
    "self-probe: the raw db.close() under a running job went through cleanly — the scenario cannot fail")
ok(f"self-probe: raw store.db.close() under a running job breaks it (exit {code}, {out or 'no output'})")

for _ in range(3):
    code, out, err = race("close")
    assert code == 0 and out == "closed=True job_done=True", (code, out, err[-2000:])
ok("close() under a running job: no crash, the job finishes all its writes, then the database closes (3 runs)")


# ---------- after close: refused, closed, idempotent ----------
a = make()
first, second = a.close(), a.close()
assert first is True and second is True
for box in (a._outbox, a._notice_outcome, a._oidc_outcome):
    assert box.closed
try:
    a.store.get_user(1)
    raise AssertionError("store still usable after close()")
except sqlite3.ProgrammingError:
    pass
ok("close() closes the database (ProgrammingError afterwards) and is idempotent")

ran, dropped = [], []
taken = a._notice_outcome.enqueue(lambda: ran.append(1))
assert taken is False
asyncio.run(a._outbox.afterwards(lambda: ran.append(2), at_overflow=lambda: dropped.append(1))())
assert ran == [] and dropped == [1], (ran, dropped)
ok("after close(): enqueue refuses (False, no exception), afterwards drops and runs the cleanup")


# ---------- deadline: a job that does not finish keeps the database open ----------
a = make()
release, inside = threading.Event(), threading.Event()


def hanging():
    inside.set()
    release.wait(10)
    a.audit("late_write", "probe")      # still needs the connection after the deadline


taken = a._notice_outcome.enqueue(hanging)
assert taken
inside.wait(5)
logging.disable(logging.WARNING)
t0 = time.monotonic()
result = a.close(timeout=0.2)
logging.disable(logging.NOTSET)
assert result is False and time.monotonic() - t0 < 2, result
assert a.store.get_user(1) is None, "store closed although a job was still running"
taken = a._notice_outcome.enqueue(lambda: None)
assert taken is False, "a new job was taken during the shutdown"
release.set()
a._notice_outcome.wait()
assert any(r["event"] == "late_write" for r in a.store.recent_audit(5)), "the late job could not write"
closed = a.close()
assert closed is True
ok("deadline passed with a running job: close() returns False, database stays open; the next close() finishes")


# ---------- Store.close waits for the lock holder ----------
a = make()
store = a.store
holding, let_go, closed_at = threading.Event(), threading.Event(), []


def holder():
    with store._lock:
        holding.set()
        let_go.wait(5)
        store.db.execute("SELECT 1").fetchone()    # the statement runs to its end


th = threading.Thread(target=holder)
th.start()
holding.wait(5)
closer = threading.Thread(target=lambda: (store.close(), closed_at.append(time.monotonic())))
closer.start()
time.sleep(0.2)
assert not closed_at, "Store.close() did not wait for the statement under the lock"
released = time.monotonic()
let_go.set()
th.join(5)
closer.join(5)
assert closed_at and closed_at[0] >= released
ok("Store.close() waits for a statement running under the store lock")


# ---------- lifespan and context manager ----------
a = make()
app = FastAPI(lifespan=a.lifespan)
app.include_router(a.router())
with TestClient(app) as c:
    assert c.get("/auth/me").status_code == 401
    assert not a._closed
assert a._closed and a._outbox.closed
ok("FastAPI(lifespan=auth.lifespan): close() at shutdown")

with make() as b:
    assert not b._closed
assert b._closed
ok("with TinySesam(cfg) as auth: close() at the end of the block")

cfg = TinySesamConfig.oidc_gateway(
    csrf_enabled=False, issuer="https://id.example.invalid", client_id="cid", client_secret="sec",
    base_url="https://auth.example.com", trusted_redirect_hosts=["app.example.com"],
    db_path=os.path.join(tempfile.mkdtemp(), "g.db"))
gapp = gateway.build_app(cfg)
with TestClient(gapp) as c:
    assert c.get("/healthz").status_code == 200
logging.disable(logging.ERROR)
after = TestClient(gapp).get("/healthz")       # without lifespan: the database is closed now
logging.disable(logging.NOTSET)
assert after.status_code == 503, after.status_code
ok("gateway: the lifespan closes the database at shutdown (/healthz 503 afterwards)")


# ---------- Outbox.close alone ----------
box = Outbox(worker=1)
seen = []
taken = box.enqueue(lambda: (time.sleep(0.05), seen.append(1)))
closed = box.close(5)
assert taken and closed is True and seen == [1]
taken = box.enqueue(lambda: seen.append(2))
assert taken is False and seen == [1]
ok("Outbox.close(): waits for the queued job, then refuses")

print("test_close: all checks passed")

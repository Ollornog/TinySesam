---
id: T-67
type: Task
title: 'Orderly shutdown: a public close() that drains the outboxes and refuses new jobs'
status: erledigt
milestone: M-2
tags: [api, lifecycle, tests]
created: '2026-11-20'
---
# T-67 — Orderly shutdown: a public close() that drains the outboxes and refuses new jobs

Origin: [B-13](B-13-flaky-ci-suite-died-silently-and-chrome-start.md).

**Situation:** TinySesam has no way to shut down. The background outboxes (`tinysesam.mailer.Outbox`, notices and
OIDC jobs) use the store's single `sqlite3` connection from a worker thread. Whoever closes that connection while a
job runs crashes the process (segmentation fault in `sqlite3`). The library itself never closes it, and at process
end the workers are joined first — measured in B-13, production is not affected. But an embedding app (its own
lifespan shutdown, a test that restarts the library on the same file) can only reach for `auth.store.db.close()`,
which is tier C and unsafe. The test suites do exactly that; `tests/_starter.py` makes it safe in the test process
only.

**Proposal:** `TinySesam.close()` (tier A, idempotent):
- stop taking jobs: `enqueue`/`afterwards` after close refuse (logged, not raised — a request in flight must not
  fail because of it);
- wait for the queued jobs (with a deadline), then shut the executors down;
- close the store under its lock (`Store.close()`), so no thread uses the connection at the same time;
- optionally a context manager / lifespan helper for FastAPI.

Then the suites call `auth.close()` instead of `store.db.close()`, and the drain in `tests/_starter.py` becomes a
mere safety net or goes. Needs `tests/api_surface.json`, API.md, a test with mutation (close under a running job:
no crash, job done or refused, new job refused).

## Done (2026-11-21)

- `Outbox.close(timeout)`: refuses new jobs (`enqueue` → False, `afterwards` drops and runs its cleanup), counts jobs
  in the worker itself and waits for them under one lock with the refusal, then shuts the pool down.
- `Store.close()`: closes the connection under the store lock.
- `TinySesam.close(timeout=10.0)` (tier A): all three outboxes within one deadline, then the store; idempotent;
  `False` (database stays open) if a job outlives the deadline. `TinySesam.lifespan` (tier A) for FastAPI,
  `__enter__`/`__exit__` for scripts. The gateway uses the lifespan.
- Suites call `auth.close()` / `Store.close()` instead of `store.db.close()`; the drain in `tests/_starter.py` stays as
  a safety net.
- `tests/test_close.py`: self-probe (raw `db.close()` under a running job: segmentation fault in a subprocess),
  `close()` under the same job three times clean, deadline, lock wait, lifespan, gateway, context manager.

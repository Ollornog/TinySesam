---
id: T-38
type: Task
title: 'Gateway: no /docs, /redoc, /openapi.json without sign-in'
status: erledigt
milestone: M-5
tags: [gateway, security, asvs]
created: '2026-11-20'
---
# T-38 — Gateway: no /docs, /redoc, /openapi.json without sign-in

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding M2 — ASVS 13.4.5 (L2), own rule "load nothing from third parties".

**Was:** `tinysesam/gateway.py` built `FastAPI(title=…)` with FastAPI's defaults. Measured: `/docs` answered 200 without
a CSP and loaded Swagger UI from a third-party CDN; `/openapi.json` answered 200 with every route including the admin API.

## Done (H1)
- `build_app()`: `docs_url=None, redoc_url=None, openapi_url=None` — no switch: nobody operates the gateway through
  them, the schema stays readable in Python (`build_app(cfg).openapi()`).
- `examples/demo.py`, `examples/showcase.py` the same (examples get copied); README (en/de): note for own apps.
- `tests/test_gateway.py`: the four paths answer 404 and contain no CDN/Swagger reference.
- Not here: `/healthz` names the version (ASVS 13.4.6, L3) → T-52.

---
id: B-5
type: Bug
title: 'Gateway: forward auth of a WebSocket app answers 403 when a WebSocket library is installed'
status: erledigt
milestone: M-2
tags: [gateway, forward-auth, websocket]
created: 2026-10-29
---

# B-5 — Gateway: forward auth of a WebSocket app answers 403 when a WebSocket library is installed

Found 2026-10-29 after the 0.25.0 rollout: the gateway logged "Unsupported upgrade request / No supported WebSocket library detected" for forward-auth requests. The check of a WebSocket app arrives with the client's `Upgrade: websocket` — the proxy copies the headers into the subrequest. The image has no WebSocket library, so uvicorn answered it as plain HTTP (correct) and logged the warning pair. Measured with `websockets` installed and uvicorn's default `ws="auto"`: the same request is taken for a handshake and answered **403** — a pip install with `uvicorn[standard]` locked every WebSocket app out. `ws="none"` alone does not silence the warnings (uvicorn logs them whenever it has no WebSocket protocol).

Fixed: `python -m tinysesam.gateway` starts uvicorn with `ws="none"` (`gateway._server_config`) and drops exactly the two warnings on `uvicorn.error`; your own `uvicorn tinysesam.gateway:app` needs `--ws none` (README, `--help`). Test `tests/test_gateway.py` through a real uvicorn; mutations: `ws="auto"` and the filter not installed → red.

# OAuth end-to-end check with the real Claude Code CLI (T-36)

Manual and optional — not part of the CI, because it needs the `claude` CLI, Docker, Google Chrome and OpenSSL.
It checks the acceptance list of [T-36](../../backlog/T-36-oauth-authorization-server-for-mcp-clients.md) against
the real client:

1. `claude mcp add --transport http …` → sign-in (password + TOTP + consent) → the MCP tool answers as the account
2. a new CLI process after the access token expired works without a sign-in (silent refresh)
3. the device is disconnected on the account page → 401 → a new sign-in is needed
4. an old refresh token presented again → the family is revoked (audit) → a new sign-in is needed
5. the account is locked → access gone at once
6. `claude mcp logout` revokes the tokens at the server (RFC 7009)

```bash
pip install -e ".[all]" uvicorn websockets pyotp
python tools/oauth-e2e/e2e.py            # throwaway directory; --work DIR --keep to look at it afterwards
```

Everything listens on 127.0.0.1 only. The proxy is Caddy (pinned image) with a Caddyfile generated from
`deploy/forward-auth/Caddyfile` — the template is part of what is tested. `CLAUDE_CONFIG_DIR` points into the work
directory, so your own Claude Code configuration is never read or written; no Anthropic account is used: a local
model stand-in (`ANTHROPIC_BASE_URL`) answers with a `tool_use`, and the CLI itself executes the MCP `tools/call`.
Each step prints ✅/❌; the evidence (CLI output, audit lines, callback URLs without the code) is in
`<work>/report.jsonl`.

## Services: the reference client against the real server (T-60)

`services_e2e.py` checks [T-60](../../backlog/T-60-oauth-for-services-client-credentials-private-key-jwt.md) end to
end: TinySesam with `oauth_service_clients` under uvicorn, Caddy (the same generated Caddyfile) in front of a small
application that echoes the `Remote-*` headers, and `tinysesam-client` as a separate process. It needs Docker and
OpenSSL, not the `claude` CLI or Chrome.

1. pairing with a one-time code → key file 0600, only the public key at the server
2. a request through Caddy → `Remote-User` of the service account with its roles, never the admin flag
3. no token → 401 (Bearer); the token outside its resource → not let through
4. the same client assertion twice → the second refused (replay), reason in the audit log
5. `tinysesam-client rotate` → new key; a token from before and the old key keep working (overlap)
6. `httpx` with `ServiceClient.httpx_auth()` → 200
7. the service account locked → the held token refused at once, no new one

```bash
pip install -e ".[all]" uvicorn httpx
python tools/oauth-e2e/services_e2e.py   # --work DIR --keep to look at it afterwards
```

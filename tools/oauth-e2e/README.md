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

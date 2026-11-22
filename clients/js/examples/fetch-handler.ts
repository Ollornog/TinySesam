// A Fetch handler (Deno, Bun, edge runtimes; Hono with `c.req.raw`) in token mode with the key set from TinySesam.
//
// Token mode needs the gate token delivered to the application (backlog T-84): with today's proxy template the gate
// cookie is removed before the application. Header mode works the same way with `mode: 'header'`.

import { createGate, guardResponse, identifyRequest, withGate } from '../src/index.ts';

const gate = await createGate({
  mode: 'token',
  issuer: 'https://auth.example.com', // TinySesam's base_url, exactly
  audience: 'app.example.com', // the exact audience_whitelist entry of this route
  jwksUrl: 'https://auth.example.com/auth/gate/jwks.json',
});

/** Editors only: 401 without identity, 403 without the role. */
export const editors = withGate(gate, [{ role: 'editors' }], (_request, identity) => {
  return Response.json({ id: identity.id, user: identity.user, groups: identity.groups });
});

/** The same by hand, e.g. inside a Hono middleware: `const id = await identifyRequest(gate, c.req.raw)`. */
export async function handle(request: Request): Promise<Response> {
  const identity = await identifyRequest(gate, request);
  const denied = guardResponse(identity, ['session']);
  if (denied !== null || identity === null) {
    return denied ?? new Response('Unauthorized', { status: 401 });
  }
  return new Response(`hello ${identity.user}`);
}

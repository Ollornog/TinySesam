// The Fetch API adapter (web standard: Hono, Deno, Bun, edge runtimes, service workers).
//
// Limit: the Fetch `Headers` API joins repeated fields with ", " — a request that carries Remote-User twice arrives
// as one value here, so the repeat check of spec section 2.2 cannot see it. In header mode, rely on duty 1 of spec
// section 2.1 (the proxy removes every Remote-* header the client sent) and, on Node, prefer the adapter in `./node`,
// which reads the raw field lines.

import type { Gate, GateRequest } from './gate.ts';
import { authorize, DENY_HEADERS, type Requirement, statusText } from './guards.ts';
import type { Identity } from './identity.ts';

/** The gate's view of a Fetch request; `peer` is the socket address the runtime reports, if any. */
export function fromFetchRequest(request: Request, peer?: string | null): GateRequest {
  return { headers: [...request.headers], peer: peer ?? null };
}

/** The identity of a Fetch request, or null (refusals go to the gate's logger). */
export function identifyRequest(gate: Gate, request: Request, peer?: string | null): Promise<Identity | null> {
  return gate.identifyOrNull(fromFetchRequest(request, peer));
}

/** A refusal: 401 or 403 with the status text, `Cache-Control: no-store`, nothing else. */
export function denyResponse(status: 401 | 403): Response {
  return new Response(statusText(status), { status, headers: DENY_HEADERS });
}

/** A guard for Fetch handlers: null when the identity meets the requirements, otherwise the 401/403 response. */
export function guardResponse(
  identity: Identity | null | undefined,
  requirements: readonly Requirement[] = [],
): Response | null {
  const decision = authorize(identity, requirements);
  return decision === 'allow' ? null : denyResponse(decision);
}

/**
 * Wraps a Fetch handler: identifies the request, answers 401/403 unless the requirements are met, and hands the
 * identity to the handler.
 */
export function withGate(
  gate: Gate,
  requirements: readonly Requirement[],
  handler: (request: Request, identity: Identity) => Response | Promise<Response>,
  options: { peer?: (request: Request) => string | null | undefined } = {},
): (request: Request) => Promise<Response> {
  return async (request) => {
    const identity = await identifyRequest(gate, request, options.peer?.(request));
    const denied = guardResponse(identity, requirements);
    if (denied !== null || identity === null) {
      return denied ?? denyResponse(401);
    }
    return handler(request, identity);
  };
}

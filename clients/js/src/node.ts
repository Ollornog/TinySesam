// The Node adapter: plain `node:http` and Express-compatible middleware. Type imports only — no Node module is loaded
// at runtime, but this entry point is meant for Node (and runtimes that emulate node:http).

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Gate, GateRequest } from './gate.ts';
import { authorize, DENY_HEADERS, type Requirement, statusText } from './guards.ts';
import type { HeaderPairs, Identity } from './identity.ts';

/** A Connect/Express middleware. */
export type Middleware = (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => void;

/** The raw field lines of a Node request as pairs: repeated fields stay separate, values are octets (latin1). */
export function rawHeaderPairs(req: IncomingMessage): HeaderPairs {
  const raw = req.rawHeaders;
  const out: [string, string][] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) {
    out.push([raw[i] ?? '', raw[i + 1] ?? '']);
  }
  return out;
}

/** The gate's view of a Node request: the raw field lines and the socket's peer address (not X-Forwarded-For). */
export function fromNodeRequest(req: IncomingMessage): GateRequest {
  return { headers: rawHeaderPairs(req), peer: req.socket?.remoteAddress ?? null };
}

// The identity per request lives here, not on a property of the request that another layer could set.
const identities = new WeakMap<IncomingMessage, Identity | null>();

/** The identity {@link gateMiddleware} stored for this request, or null. */
export function identityOf(req: IncomingMessage): Identity | null {
  return identities.get(req) ?? null;
}

/**
 * Identifies every request and stores the identity (read it with {@link identityOf}). It lets every request through;
 * guard routes with {@link requireAuth}, {@link requireRole} or {@link requireSession}.
 */
export function gateMiddleware(gate: Gate): Middleware {
  return (req, _res, next) => {
    // Cleared first: an identity from an earlier layer never survives a failed check here.
    identities.set(req, null);
    gate.identifyOrNull(fromNodeRequest(req)).then(
      (identity) => {
        identities.set(req, identity);
        next();
      },
      () => next(),
    );
  };
}

/** Answers 401/403 without the token, the claims or the reason. */
export function deny(res: ServerResponse, status: 401 | 403): void {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.statusCode = status;
  for (const [name, value] of Object.entries(DENY_HEADERS)) {
    res.setHeader(name, value);
  }
  res.end(statusText(status));
}

/** A middleware that lets the request through only when the stored identity meets the requirements. */
export function requireAll(...requirements: Requirement[]): Middleware {
  return (req, res, next) => {
    const decision = authorize(identityOf(req), requirements);
    if (decision === 'allow') {
      next();
    } else {
      deny(res, decision);
    }
  };
}

/** 401 unless the request carries an identity. */
export function requireAuth(): Middleware {
  return requireAll('signed-in');
}

/** 401 without an identity, 403 when the role is not one of its groups (compared exactly). */
export function requireRole(role: string): Middleware {
  return requireAll({ role });
}

/**
 * 401 without an identity, 403 unless the request came from a browser session — for actions a token must never
 * perform, and for decisions that need the complete groups.
 */
export function requireSession(): Middleware {
  return requireAll('session');
}

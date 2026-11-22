// A plain node:http server behind TinySesam's gate in header mode, with the middleware and three guards.
//
//   node examples/node-http.ts         (Node >= 22.18 runs TypeScript directly)
//
// Bind to loopback only: the proxy is the only way in (spec section 2.1, duty 3).

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createGate } from '../src/index.ts';
import { gateMiddleware, identityOf, type Middleware, requireRole, requireSession } from '../src/node.ts';

const gate = await createGate({
  mode: 'header',
  trustedProxies: ['127.0.0.1', '::1'], // the proxy's address; every other peer is refused
  logger: (event) => console.warn('gate refused a request', event), // class and kid only, never a value
});

/** Runs the middlewares in order, then the handler. */
function chain(middlewares: Middleware[], handler: (req: IncomingMessage, res: ServerResponse) => void) {
  return (req: IncomingMessage, res: ServerResponse) => {
    let i = 0;
    const next = (err?: unknown) => {
      if (err) {
        res.statusCode = 500;
        res.end();
        return;
      }
      const m = middlewares[i++];
      if (m) {
        m(req, res, next);
      } else {
        handler(req, res);
      }
    };
    next();
  };
}

const identify = gateMiddleware(gate);

const server = createServer((req, res) => {
  if (req.url === '/admin') {
    // A browser session with the role "admin": a token request never carries admin.
    return chain([identify, requireSession(), requireRole('admin')], (_req, r) => r.end('admin area\n'))(req, res);
  }
  return chain([identify], (r, out) => {
    const id = identityOf(r);
    out.setHeader('content-type', 'text/plain; charset=utf-8');
    // Names are text: escape them before they go into HTML.
    out.end(id ? `signed in as ${id.user} (id ${id.id}, ${id.kind})\n` : 'not signed in\n');
  })(req, res);
});

server.listen(8080, '127.0.0.1');

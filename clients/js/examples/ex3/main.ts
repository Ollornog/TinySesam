// Example Ex3 (T-102, T-104): a Node application behind the TinySesam server, surface "hybrid".
//
//   TS_AUTH_URL=https://auth.example.com node examples/ex3/main.ts      (Node >= 22.18 runs TypeScript directly)
//
// The application draws its own navigation — Documents, About and one link "Account" — and leaves everything of the
// account to TinySesam's area (`<TS_AUTH_URL>/auth/area?app=docs`): sign-in, security, sessions, the panel, all in
// the application's frame with a way back. The people come from the identity provider (their groups become roles,
// T-102) or are local accounts of TinySesam — mixed. The identity comes from the Remote-* headers of the proxy only
// (spec section 2.1); the documents need the permission docs.read, which an administrator gives a role in the panel.
// Bind to loopback or the compose network only: the proxy is the only way in.

import { randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createGate, type Identity } from '../../src/index.ts';
import { gateMiddleware, identityOf } from '../../src/node.ts';

const APP = 'docs';
const AUTH_URL = (process.env.TS_AUTH_URL ?? '').replace(/\/$/, '');
if (!/^https?:\/\/[^/]+$/.test(AUTH_URL)) {
  throw new Error('TS_AUTH_URL is not set (the address of TinySesam, e.g. https://auth.example.com)');
}
const proxies = ['127.0.0.1', '::1'];
if (process.env.TS_TRUSTED_PROXY) {
  proxies.push(process.env.TS_TRUSTED_PROXY);
}
const gate = await createGate({ mode: 'header', trustedProxies: proxies });
const identify = gateMiddleware(gate);

const DOCUMENTS: readonly (readonly [string, string])[] = [
  ['d1', 'Quarterly report'],
  ['d2', 'Meeting notes'],
];

/** Text into HTML: every character that could leave the text. */
function e(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** The page's own CSS: colours only through TinySesam's --ts-* tokens, which /.tinysesam/shell.css brings. */
const STYLE =
  'body{margin:0;background:var(--ts-bg);color:var(--ts-ink);font-family:var(--ts-font)}' +
  '.nav{display:flex;flex-wrap:wrap;gap:4px 18px;align-items:center;padding:12px 16px;' +
  'border-bottom:1px solid var(--ts-line);background:var(--ts-surface)}' +
  '.nav b{margin-right:auto}.nav a{color:var(--ts-link);text-decoration:none;padding:12px 0}' +
  '.nav a[aria-current=page]{text-decoration:underline}' +
  'main{max-width:760px;margin:0 auto;padding:24px 16px}main li{margin:6px 0}';

/** Light/dark like TinySesam's pages: the choice in localStorage.themeMode, else the system's. */
const THEME =
  "(function(){var m=null;try{m=localStorage.getItem('themeMode')}catch(x){}" +
  "document.documentElement.classList.toggle('dark',m==='dark'||(m!=='light'&&" +
  "matchMedia('(prefers-color-scheme: dark)').matches))})();";

/** One page with the application's own navigation and a strict CSP: a fresh nonce for its style and script. */
function page(res: ServerResponse, status: number, title: string, current: string, body: string): void {
  const nonce = randomBytes(16).toString('base64url');
  const link = (href: string, text: string) =>
    `<a href="${e(href)}"${href === current ? ' aria-current="page"' : ''}>${e(text)}</a>`;
  res.statusCode = status;
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.setHeader(
    'content-security-policy',
    `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; ` +
      "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
  );
  res.end(
    `<!doctype html><html lang=en><head><meta charset=utf-8>` +
      `<meta name=viewport content="width=device-width,initial-scale=1"><title>${e(title)}</title>` +
      `<link rel=icon href="data:,"><script nonce="${nonce}">${THEME}</script>` +
      `<link rel=stylesheet href="/.tinysesam/shell.css" nonce="${nonce}"><style nonce="${nonce}">${STYLE}</style>` +
      `</head><body><nav class=nav aria-label="Documents"><b>Documents</b>${link('/', 'Documents')}` +
      `${link('/about', 'About')}${link(`${AUTH_URL}/auth/area?app=${APP}`, 'Account')}</nav>` +
      `<main><h1>${e(title)}</h1>${body}</main></body></html>`,
  );
}

/** Who is signed in, as text; names may hold any character but controls — escaped and isolated as bidi text. */
function who(id: Identity): string {
  return `<p id=who>Signed in as <bdi>${e(id.name || id.user)}</bdi>.</p>`;
}

const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  identify(req, res, () => {
    const id = identityOf(req);
    const path = (req.url ?? '/').split('?')[0];
    if (!id) {
      // Behind the proxy this never happens: forward auth sends the browser to TinySesam's sign-in first.
      page(res, 401, 'Not signed in', '', `<p><a href="${e(AUTH_URL)}/auth/login">Sign in</a></p>`);
    } else if (path === '/') {
      if (!id.hasPermission(`${APP}.read`)) {
        page(res, 403, 'Documents', '/', `${who(id)}<p id=denied>You may not read the documents yet.</p>`);
        return;
      }
      const rows = DOCUMENTS.map(([key, title]) => `<li id="doc-${key}">${e(title)}</li>`).join('');
      page(res, 200, 'Documents', '/', `${who(id)}<ul>${rows}</ul>`);
    } else if (path === '/about') {
      page(res, 200, 'About', '/about', `${who(id)}<p>The documents of the team, behind TinySesam.</p>`);
    } else {
      page(res, 404, 'Not found', '', '<p>No such page.</p>');
    }
  });
});

const listen = process.env.TS_LISTEN ?? '127.0.0.1:9003';
const colon = listen.lastIndexOf(':');
server.listen(Number(listen.slice(colon + 1)), listen.slice(0, colon));

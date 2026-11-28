// Example Ex4 (T-105): a single-page application behind the TinySesam server, surface "headless".
//
//   TS_AUTH_URL=https://auth.example.com node examples/ex4/main.ts      (Node >= 22.18 runs TypeScript directly)
//
// The application draws everything itself: its navigation, the documents and its own settings page. The settings
// page is a single-page app in the browser (examples/ex4/app.js): it reads the account's state from
// /.tinysesam/account.json on this host (the proxy passes /.tinysesam/* to TinySesam) and changes nothing itself —
// every change is a link to one of TinySesam's action pages (spec section 8c), which leads back here with
// ts_action, ts_result and state. No password, code or key ever passes through this program or its page.
// The identity comes from the Remote-* headers of the proxy only (spec section 2.1). Bind to loopback or the compose
// network only: the proxy is the only way in.

import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createGate } from '../../src/index.ts';
import { gateMiddleware, identityOf } from '../../src/node.ts';

const APP = 'docs';
const proxies = ['127.0.0.1', '::1'];
if (process.env.TS_TRUSTED_PROXY) {
  proxies.push(process.env.TS_TRUSTED_PROXY);
}
const gate = await createGate({ mode: 'header', trustedProxies: proxies });
const identify = gateMiddleware(gate);
const SCRIPT = readFileSync(new URL('./app.js', import.meta.url), 'utf8');

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
  'main{max-width:760px;margin:0 auto;padding:24px 16px}' +
  'section{border:1px solid var(--ts-line);border-radius:10px;background:var(--ts-surface);padding:12px 16px;' +
  'margin:0 0 14px}section h2{font-size:15px;margin:0 0 8px}' +
  'ul{list-style:none;padding:0;margin:0}li{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;' +
  'padding:6px 0;border-bottom:1px solid var(--ts-line-soft)}li:last-child{border-bottom:0}' +
  'li span{flex:1 1 200px}a.act{display:inline-flex;align-items:center;min-height:44px;padding:0 14px;' +
  'border-radius:8px;background:var(--ts-neutral);color:var(--ts-neutral-ink);text-decoration:none}' +
  '#notice{border-radius:8px;padding:10px 14px;margin:0 0 14px;border:1px solid var(--ts-line)}' +
  '#notice[hidden]{display:none}';

/** Light/dark like TinySesam's pages: the choice in localStorage.themeMode, else the system's. */
const THEME =
  "(function(){var m=null;try{m=localStorage.getItem('themeMode')}catch(x){}" +
  "document.documentElement.classList.toggle('dark',m==='dark'||(m!=='light'&&" +
  "matchMedia('(prefers-color-scheme: dark)').matches))})();";

/** One page with the application's own navigation and a strict CSP: a fresh nonce for its style and scripts. */
function page(res: ServerResponse, status: number, title: string, current: string, body: string, script = ''): void {
  const nonce = randomBytes(16).toString('base64url');
  const link = (href: string, text: string) =>
    `<a href="${e(href)}"${href === current ? ' aria-current="page"' : ''}>${e(text)}</a>`;
  res.statusCode = status;
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  // connect-src 'self': the page reads /.tinysesam/account.json on its own host and nothing else.
  res.setHeader(
    'content-security-policy',
    `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; ` +
      "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
  );
  res.end(
    `<!doctype html><html lang=en><head><meta charset=utf-8>` +
      `<meta name=viewport content="width=device-width,initial-scale=1"><title>${e(title)}</title>` +
      `<link rel=icon href="data:,"><script nonce="${nonce}">${THEME}</script>` +
      `<link rel=stylesheet href="/.tinysesam/shell.css" nonce="${nonce}"><style nonce="${nonce}">${STYLE}</style>` +
      `</head><body><nav class=nav aria-label="Documents"><b>Documents</b>${link('/', 'Documents')}` +
      `${link('/settings', 'Settings')}</nav><main><h1>${e(title)}</h1>${body}</main>` +
      (script ? `<script nonce="${nonce}">${script}</script>` : '') +
      `</body></html>`,
  );
}

const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  identify(req, res, () => {
    const id = identityOf(req);
    const path = (req.url ?? '/').split('?')[0];
    if (!id) {
      // Behind the proxy this never happens: forward auth sends the browser to TinySesam's sign-in first.
      page(res, 401, 'Not signed in', '', '<p>Not signed in.</p>');
    } else if (path === '/') {
      const who = `<p id=who>Signed in as <bdi>${e(id.name || id.user)}</bdi>.</p>`;
      if (!id.hasPermission(`${APP}.read`)) {
        page(res, 403, 'Documents', '/', `${who}<p id=denied>You may not read the documents yet.</p>`);
        return;
      }
      page(res, 200, 'Documents', '/', `${who}<ul><li id=doc-d1>Quarterly report</li></ul>`);
    } else if (path === '/settings') {
      // The settings page is drawn in the browser from account.json (app.js); the server sends only the frame.
      const body = '<p id=notice role=status hidden></p><div id=settings aria-live=polite><p>Loading…</p></div>';
      page(res, 200, 'Settings', '/settings', body, SCRIPT);
    } else {
      page(res, 404, 'Not found', '', '<p>No such page.</p>');
    }
  });
});

const listen = process.env.TS_LISTEN ?? '127.0.0.1:9004';
const colon = listen.lastIndexOf(':');
server.listen(Number(listen.slice(colon + 1)), listen.slice(0, colon));

// The gate around the checks: configuration errors that stop the start, token sources, header mode with trusted
// proxies, the Node and Fetch adapters, guards, logging, the top bar fetch.

import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { type AddressInfo, connect } from 'node:net';
import { test } from 'node:test';
import { ConfigError, GateError } from '../src/errors.ts';
import { guardResponse, identifyRequest, withGate } from '../src/fetch.ts';
import { createGate, Gate, type GateConfig } from '../src/gate.ts';
import { authorize } from '../src/guards.ts';
import { Identity } from '../src/identity.ts';
import { StaticKeys } from '../src/jwks.ts';
import { parseJwks } from '../src/keys.ts';
import { gateMiddleware, identityOf, requireAuth, requireRole, requireSession } from '../src/node.ts';
import { fetchTopbar, parseTopbar, tinysesamCookies } from '../src/topbar.ts';
import {
  DEFAULTS,
  type Json,
  loadVectors,
  mint,
  mintRaw,
  outcome,
  publicJwk,
  sessionClaims,
  signKey,
} from './helpers.ts';

const TOKEN_BASE = { mode: 'token', issuer: DEFAULTS.issuer, audience: DEFAULTS.audience } as const;

test('configuration errors stop the start', async () => {
  const bad: [string, unknown][] = [
    ['no configuration', undefined],
    ['no mode', {}],
    ['unknown mode', { mode: 'auto' }],
    ['token setting in header mode', { mode: 'header', issuer: 'x' }],
    ['misspelt header setting', { mode: 'header', trustedProxy: ['127.0.0.1'] }],
    ['empty trusted proxy list', { mode: 'header', trustedProxies: [] }],
    ['invalid trusted proxy', { mode: 'header', trustedProxies: ['127.0.0.300'] }],
    ['trusted proxy with a zone', { mode: 'header', trustedProxies: ['fe80::1%eth0'] }],
    ['prefix too long', { mode: 'header', trustedProxies: ['198.51.100.0/33'] }],
    ['invalid header name', { mode: 'header', headerNames: { user: 'Remote User' } }],
    ['two equal header names', { mode: 'header', headerNames: { name: 'remote-user' } }],
    ['logger not a function', { mode: 'header', logger: 'console' }],
    ['header setting in token mode', { ...TOKEN_BASE, gateKeys: [signKey('A')], trustedProxies: ['127.0.0.1'] }],
    ['no issuer', { mode: 'token', audience: 'a', gateKeys: [signKey('A')] }],
    ['empty audience', { ...TOKEN_BASE, audience: '', gateKeys: [signKey('A')] }],
    ['no key', { ...TOKEN_BASE }],
    ['empty key list', { ...TOKEN_BASE, gateKeys: [] }],
    ['bad key', { ...TOKEN_BASE, gateKeys: ['not base64'] }],
    ['key of 31 bytes', { ...TOKEN_BASE, gateKeys: [btoa('x'.repeat(31))] }],
    ['key in base64url', { ...TOKEN_BASE, gateKeys: [publicJwk('A').x] }],
    ['both key sources', { ...TOKEN_BASE, gateKeys: [signKey('A')], jwksUrl: 'https://auth.example.com/j' }],
    ['fetch without jwksUrl', { ...TOKEN_BASE, gateKeys: [signKey('A')], fetch: globalThis.fetch }],
    ['jwksUrl over plain http', { ...TOKEN_BASE, jwksUrl: 'http://auth.example.com/auth/gate/jwks.json' }],
    ['jwksUrl with credentials', { ...TOKEN_BASE, jwksUrl: 'https://u:p@auth.example.com/j' }],
    ['jwksUrl not absolute', { ...TOKEN_BASE, jwksUrl: '/auth/gate/jwks.json' }],
    ['jwksUrl ftp', { ...TOKEN_BASE, jwksUrl: 'ftp://auth.example.com/j' }],
    ['approval key set', { ...TOKEN_BASE, jwksUrl: 'https://auth.example.com/auth/approvals/jwks.json' }],
    ['approval key set /', { ...TOKEN_BASE, jwksUrl: 'https://auth.example.com/auth/approvals/jwks.json/' }],
    ['leeway above 60', { ...TOKEN_BASE, gateKeys: [signKey('A')], leewaySeconds: 61 }],
    ['negative leeway', { ...TOKEN_BASE, gateKeys: [signKey('A')], leewaySeconds: -1 }],
    ['fractional leeway', { ...TOKEN_BASE, gateKeys: [signKey('A')], leewaySeconds: 1.5 }],
    ['cookie and header', { ...TOKEN_BASE, gateKeys: [signKey('A')], cookieName: 'c', tokenHeader: 'X-Gate' }],
    ['invalid token header', { ...TOKEN_BASE, gateKeys: [signKey('A')], tokenHeader: 'X Gate' }],
    ['invalid cookie name', { ...TOKEN_BASE, gateKeys: [signKey('A')], cookieName: 'a;b' }],
  ];
  for (const [why, config] of bad) {
    await assert.rejects(createGate(config as GateConfig), ConfigError, why);
  }
  const good: GateConfig[] = [
    { mode: 'header' },
    { mode: 'header', trustedProxies: ['127.0.0.1', '::1', '198.51.100.0/24', '2001:db8::/32'] },
    { ...TOKEN_BASE, gateKeys: [signKey('A'), signKey('B')], leewaySeconds: 60 },
    { ...TOKEN_BASE, jwksUrl: 'https://auth.example.com/auth/gate/jwks.json' },
    { ...TOKEN_BASE, jwksUrl: 'http://127.0.0.1:8080/auth/gate/jwks.json' },
    { ...TOKEN_BASE, jwksUrl: 'http://[::1]:8080/auth/gate/jwks.json' },
    { ...TOKEN_BASE, jwksUrl: 'http://localhost/auth/gate/jwks.json' },
  ];
  for (const config of good) {
    assert.ok(await createGate(config), JSON.stringify(config));
  }
});

const enc = new TextEncoder();

/** A gate at the vectors' clock with test key A. */
async function fixedGate(extra: { cookie?: string; tokenHeader?: string; leeway?: number } = {}): Promise<Gate> {
  return new Gate({
    mode: 'token',
    rules: { issuer: DEFAULTS.issuer, audience: DEFAULTS.audience, leeway: extra.leeway ?? 0 },
    keys: new StaticKeys(await parseJwks(JSON.stringify({ keys: [publicJwk('A')] }))),
    ...(extra.cookie ? { cookie: extra.cookie } : {}),
    ...(extra.tokenHeader ? { tokenHeader: extra.tokenHeader } : {}),
    now: () => DEFAULTS.now,
  });
}

test('token sources: exactly one gate cookie, or the configured header', async () => {
  const gate = await fixedGate();
  const token = await mint('A', sessionClaims());
  const cookie = (v: string) => outcome(gate.identify({ headers: [['Cookie', v]] }));
  assert.equal(await cookie(`a=1; __Host-tinysesam_gate=${token}; b=2`), 'ok');
  assert.equal(await cookie(`__Host-tinysesam_gate=${token}; __Host-tinysesam_gate=${token}`), 'malformed');
  assert.equal(
    await outcome(
      gate.identify({
        headers: [
          ['cookie', `__Host-tinysesam_gate=${token}`],
          ['Cookie', `__Host-tinysesam_gate=${token}`],
        ],
      }),
    ),
    'malformed',
  );
  assert.equal(await cookie('__Host-tinysesam_gate='), 'unauthenticated');
  assert.equal(await cookie('tinysesam_gate=x'), 'unauthenticated');
  // Cookie names are case-sensitive: another spelling is another cookie.
  assert.equal(await cookie(`__host-tinysesam_gate=${token}`), 'unauthenticated');
  assert.equal(await outcome(gate.identify({ headers: [] })), 'unauthenticated');
  // Never from Authorization, a query or another header unless configured.
  assert.equal(await outcome(gate.identify({ headers: [['Authorization', `Bearer ${token}`]] })), 'unauthenticated');

  const byHeader = await fixedGate({ tokenHeader: 'X-Gate-Token' });
  assert.equal(await outcome(byHeader.identify({ headers: [['x-gate-token', token]] })), 'ok');
  assert.equal(
    await outcome(byHeader.identify({ headers: [['Cookie', `__Host-tinysesam_gate=${token}`]] })),
    'unauthenticated',
  );
  assert.equal(
    await outcome(
      byHeader.identify({
        headers: [
          ['X-Gate-Token', token],
          ['x-gate-token', token],
        ],
      }),
    ),
    'malformed',
  );
});

test('token mode ignores every Remote-* header', async () => {
  const gate = await fixedGate();
  const token = await mint('A', sessionClaims('editors'));
  const identity = await gate.identify({
    headers: [
      ['Cookie', `__Host-tinysesam_gate=${token}`],
      ['Remote-User', 'admin'],
      ['Remote-Groups', 'admin'],
      ['Remote-Auth', 'session'],
    ],
  });
  assert.equal(identity.user, 'anna');
  assert.deepEqual(identity.groups, ['editors']);
  // No token: no fall-back to the headers.
  assert.equal(await outcome(gate.identify({ headers: [['Remote-User', 'admin']] })), 'unauthenticated');
});

test('leeway: at most the configured seconds on both edges', async () => {
  const strict = await fixedGate();
  const loose = await fixedGate({ leeway: 60 });
  const at = (offset: number) => sessionClaims('editors', DEFAULTS.now + offset);
  assert.equal(await outcome(strict.verify(await mint('A', at(1)))), 'not_yet_valid');
  assert.equal(await outcome(loose.verify(await mint('A', at(60)))), 'ok');
  assert.equal(await outcome(loose.verify(await mint('A', at(61)))), 'not_yet_valid');
  assert.equal(await outcome(strict.verify(await mint('A', at(-300)))), 'expired');
  assert.equal(await outcome(loose.verify(await mint('A', at(-359)))), 'ok');
  assert.equal(await outcome(loose.verify(await mint('A', at(-360)))), 'expired');
});

test('a malformed kid never reaches the key source', async () => {
  let lookups = 0;
  const gate = new Gate({
    mode: 'token',
    rules: { issuer: DEFAULTS.issuer, audience: DEFAULTS.audience, leeway: 0 },
    keys: {
      lookup: async () => {
        lookups++;
        throw new GateError('kid');
      },
    },
    now: () => DEFAULTS.now,
  });
  for (const kid of ['A033507CA61AD979', 'a033507ca61ad97', 'a033507ca61ad9790', '../../etc/passwd', '']) {
    const header = enc.encode(JSON.stringify({ alg: 'EdDSA', typ: 'tinysesam-gate+jwt', kid }));
    const token = await mintRaw('A', header, enc.encode(JSON.stringify(sessionClaims())));
    assert.equal(await outcome(gate.verify(token)), 'kid', kid);
  }
  assert.equal(lookups, 0);
});

test('header mode: trusted proxies, renamed headers, peer addresses', async () => {
  const gate = await createGate({ mode: 'header', trustedProxies: ['127.0.0.1', '198.51.100.0/24', '::1'] });
  const headers: [string, string][] = [
    ['Remote-User', 'anna'],
    ['Remote-Auth', 'session'],
    ['Remote-Kind', 'user'],
  ];
  for (const peer of ['127.0.0.1', '::ffff:127.0.0.1', '198.51.100.3', '::1', '[::1]', '0:0:0:0:0:0:0:1']) {
    assert.equal(await outcome(gate.identify({ headers, peer })), 'ok', peer);
  }
  for (const peer of ['127.0.0.2', '203.0.113.1', '::2', '', 'localhost', null, undefined, '::ffff:7f00:2']) {
    assert.equal(await outcome(gate.identify({ headers, peer })), 'untrusted_peer', String(peer));
  }
  // Without a list every peer is accepted (the operator's duty, spec section 2.1).
  assert.equal(await outcome((await createGate({ mode: 'header' })).identify({ headers })), 'ok');

  const renamed = await createGate({ mode: 'header', headerNames: { user: 'X-User', groups: 'X-Roles' } });
  const id = await renamed.identify({
    headers: [
      ['x-user', 'anna'],
      ['X-Roles', 'a, b'],
      ['Remote-User', 'admin'],
      ['Remote-Kind', 'user'],
    ],
  });
  assert.equal(id.user, 'anna');
  assert.deepEqual(id.groups, ['a', 'b']);
  assert.equal(await outcome(renamed.identify({ headers: [['Remote-User', 'admin']] })), 'unauthenticated');
  // No identity from look-alike headers.
  const plain = await createGate({ mode: 'header' });
  for (const name of ['X-Forwarded-User', 'X-Remote-User', 'X-Auth-Request-User', 'Remote-User-Name']) {
    assert.equal(await outcome(plain.identify({ headers: [[name, 'admin']] })), 'unauthenticated', name);
  }
});

test('Remote-Auth: only exactly "session" is a session', async () => {
  const gate = await createGate({ mode: 'header' });
  for (const [auth, kind, reported] of [
    ['session', 'session', 'session'],
    ['Session', 'token', ''],
    ['oauth', 'token', 'oauth'],
    ['apikey', 'token', 'apikey'],
    ['app-password', 'token', 'app-password'],
    ['', 'token', ''],
    ['session ', 'session', 'session'], // trailing whitespace is not part of the value (the HTTP layer drops it)
  ] as const) {
    const headers: [string, string][] = [
      ['Remote-User', 'anna'],
      ['Remote-Kind', 'user'],
    ];
    if (auth.trim() !== '') {
      headers.push(['Remote-Auth', auth.trim()]);
    }
    const id = await gate.identify({ headers });
    assert.equal(id.kind, kind, auth);
    assert.equal(id.auth, reported, auth);
    assert.equal(id.isSession(), kind === 'session');
  }
});

test('account kind (spec v2): renamed header, missing value, unauthenticated first, the identity refuses a bad one', async () => {
  const renamed = await createGate({ mode: 'header', headerNames: { kind: 'X-Account-Kind' } });
  const bot = await renamed.identify({
    headers: [
      ['Remote-User', 'bot'],
      ['Remote-Auth', 'apikey'],
      ['X-Account-Kind', 'service'],
      ['Remote-Kind', 'user'],
    ],
  });
  assert.equal(bot.accountKind, 'service');
  assert.ok(bot.isService() && !bot.isSession());
  assert.equal(bot.toJSON().account_kind, 'service');
  const plain = await createGate({ mode: 'header' });
  await assert.rejects(plain.identify({ headers: [['Remote-User', 'anna']] }), (err: GateError) => {
    return err.code === 'header' && err.message.includes('older than spec v2') && !err.message.includes('anna');
  });
  assert.equal(await outcome(plain.identify({ headers: [['Remote-Groups', 'admin']] })), 'unauthenticated');
  const fields = { user: 'a', name: '', email: '', groups: '', id: '1', auth: 'session' };
  for (const accountKind of ['', 'User', 'admin']) {
    assert.throws(() => new Identity({ ...fields, accountKind }), GateError, accountKind);
  }
  assert.throws(() => new Identity({ ...fields, accountKind: 'service' }), GateError, 'service with a session');
});

test('guards: 401 without identity, 403 for a missing role or a token request', () => {
  const session = new Identity({
    user: 'a',
    name: '',
    email: '',
    groups: 'editors,admin',
    id: '1',
    auth: 'session',
    accountKind: 'user',
  });
  const token = new Identity({
    user: 'a',
    name: '',
    email: '',
    groups: 'editors',
    id: '1',
    auth: 'apikey',
    accountKind: 'user',
  });
  const service = new Identity({
    user: 'bot',
    name: '',
    email: '',
    groups: 'editors',
    id: '2',
    auth: 'apikey',
    accountKind: 'service',
  });
  assert.equal(authorize(token, [{ accountKind: 'user' }]), 'allow');
  assert.equal(authorize(service, [{ accountKind: 'user' }]), 403);
  assert.equal(authorize(service, [{ accountKind: 'service' }]), 'allow');
  assert.equal(authorize(null, [{ accountKind: 'service' }]), 401);
  assert.equal(authorize(null), 401);
  assert.equal(authorize(undefined, ['signed-in']), 401);
  assert.equal(authorize(session), 'allow');
  assert.equal(authorize(session, [{ role: 'editors' }, 'session']), 'allow');
  assert.equal(authorize(session, [{ role: 'Editors' }]), 403);
  assert.equal(authorize(session, [{ role: 'viewers' }]), 403, 'admin implies no other role');
  assert.equal(authorize(token, ['session']), 403);
  assert.equal(authorize(token, [{ role: 'editors' }]), 'allow');
  assert.equal(authorize(session, [{} as never]), 403, 'an unknown requirement denies');
  assert.equal(guardResponse(session, ['session']), null);
  const denied = guardResponse(token, ['session']);
  assert.equal(denied?.status, 403);
  assert.equal(denied?.headers.get('cache-control'), 'no-store');
});

/** One request over a raw socket (bytes as given), answered by handler; returns status and body. */
async function rawRequest(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
  head: Uint8Array,
): Promise<{ status: number; body: string }> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  try {
    const raw = await new Promise<string>((resolve, reject) => {
      const s = connect(port, '127.0.0.1', () => s.end(head));
      const chunks: Buffer[] = [];
      s.on('data', (d: Buffer) => chunks.push(d));
      s.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      s.on('error', reject);
    });
    const status = Number(raw.slice(9, 12));
    return { status, body: raw.slice(raw.indexOf('\r\n\r\n') + 4) };
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

function latin1Bytes(s: string): Uint8Array {
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

test('every header vector through a real Node HTTP server and the middleware', async () => {
  const gate = await createGate({ mode: 'header', trustedProxies: ['127.0.0.1'] });
  const middleware = gateMiddleware(gate);
  const handler = (req: IncomingMessage, res: ServerResponse) => {
    middleware(req, res, () => {
      const id = identityOf(req);
      res.end(id === null ? 'null' : JSON.stringify(id));
    });
  };
  const problems: string[] = [];
  for (const v of loadVectors('headers.json').vectors as Json[]) {
    let head = 'GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n';
    for (const [name, value] of Object.entries(v.input.headers as Record<string, string | string[]>)) {
      for (const item of Array.isArray(value) ? value : [value]) {
        head += `${name}: ${item}\r\n`;
      }
    }
    const { status, body } = await rawRequest(handler, latin1Bytes(`${head}\r\n`));
    if (v.expected.ok === true) {
      if (status !== 200 || body === 'null') {
        problems.push(`${v.id}: ${status} ${body}`);
      } else {
        try {
          // headers.json lists the identity without permissions (permissions.json checks those).
          const { permissions: _held, ...rest } = JSON.parse(body);
          assert.deepStrictEqual(rest, v.expected.identity);
        } catch {
          problems.push(`${v.id}: ${body}`);
        }
      }
    } else if (status === 200 && body !== 'null') {
      // Node's parser refusing the request (400) is a refusal too; an identity is not.
      problems.push(`${v.id}: accepted (${body}), want ${v.expected.error}`);
    }
  }
  assert.deepEqual(problems, []);
});

test('Node guards: the middleware identifies, the guards answer 401/403 without detail', async () => {
  const gate = await createGate({ mode: 'header' });
  const chain = [gateMiddleware(gate), requireAuth(), requireRole('editors'), requireSession()];
  const handler = (req: IncomingMessage, res: ServerResponse) => {
    let i = 0;
    const next = () => {
      const m = chain[i++];
      if (m) {
        m(req, res, next);
      } else {
        res.end(`hello ${identityOf(req)?.user}`);
      }
    };
    next();
  };
  const send = (headers: string) =>
    rawRequest(handler, latin1Bytes(`GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n${headers}\r\n`));
  assert.deepEqual(
    await send('Remote-User: anna\r\nRemote-Groups: editors\r\nRemote-Auth: session\r\nRemote-Kind: user\r\n'),
    {
      status: 200,
      body: 'hello anna',
    },
  );
  assert.deepEqual(await send(''), { status: 401, body: 'Unauthorized' });
  assert.deepEqual(await send('Remote-User: anna\r\nRemote-Auth: session\r\nRemote-Kind: user\r\n'), {
    status: 403,
    body: 'Forbidden',
  });
  assert.deepEqual(
    await send('Remote-User: anna\r\nRemote-Groups: editors\r\nRemote-Auth: apikey\r\nRemote-Kind: user\r\n'),
    {
      status: 403,
      body: 'Forbidden',
    },
  );
  // Guards without the middleware fail closed.
  const bare = (req: IncomingMessage, res: ServerResponse) => requireAuth()(req, res, () => res.end('through'));
  assert.equal(
    (await rawRequest(bare, latin1Bytes('GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nRemote-User: anna\r\n\r\n')))
      .status,
    401,
  );
});

test('the middleware clears an identity of an earlier pass when the check fails', async () => {
  const gate = await createGate({ mode: 'header' });
  const m = gateMiddleware(gate);
  const req = {
    rawHeaders: ['Remote-User', 'anna', 'Remote-Kind', 'user'],
    socket: { remoteAddress: '127.0.0.1' },
  } as unknown as IncomingMessage;
  await new Promise<void>((resolve) => m(req, {} as ServerResponse, () => resolve()));
  assert.equal(identityOf(req)?.user, 'anna');
  (req as unknown as { rawHeaders: string[] }).rawHeaders = ['Remote-User', 'boss\u0001', 'Remote-Kind', 'user'];
  await new Promise<void>((resolve) => m(req, {} as ServerResponse, () => resolve()));
  assert.equal(identityOf(req), null);
});

test('Fetch adapter: identifyRequest and withGate', async () => {
  const gate = await createGate({ mode: 'header', trustedProxies: ['127.0.0.1'] });
  const request = (headers: Record<string, string>) => new Request('https://app.example.com/', { headers });
  assert.equal(
    (await identifyRequest(gate, request({ 'Remote-User': 'anna', 'Remote-Kind': 'user' }), '127.0.0.1'))?.user,
    'anna',
  );
  assert.equal(
    await identifyRequest(gate, request({ 'Remote-User': 'anna', 'Remote-Kind': 'user' })),
    null,
    'no peer, untrusted',
  );
  const app = withGate(gate, [{ role: 'editors' }], (_r, id) => new Response(`hi ${id.user}`), {
    peer: () => '127.0.0.1',
  });
  assert.equal(
    await (await app(request({ 'Remote-User': 'anna', 'Remote-Groups': 'editors', 'Remote-Kind': 'user' }))).text(),
    'hi anna',
  );
  const denied = await app(request({ 'Remote-User': 'anna', 'Remote-Kind': 'user' }));
  assert.equal(denied.status, 403);
  assert.equal(await denied.text(), 'Forbidden');
  assert.equal((await app(request({}))).status, 401);
  // UTF-8 on the wire arrives as octets in Fetch Headers too.
  const utf8 = new Request('https://app.example.com/', {
    headers: [
      ['Remote-User', 'JÃ¼rgen'],
      ['Remote-Kind', 'user'],
    ],
  });
  assert.equal((await identifyRequest(gate, utf8, '127.0.0.1'))?.user, 'Jürgen');
});

test('the logger receives the class and the kid — never the token or a claim value', async () => {
  const events: unknown[] = [];
  const gate = new Gate({
    mode: 'token',
    rules: { issuer: 'https://other.example.com', audience: DEFAULTS.audience, leeway: 0 },
    keys: new StaticKeys(await parseJwks(JSON.stringify({ keys: [publicJwk('A')] }))),
    logger: (e) => events.push(e),
    now: () => DEFAULTS.now,
  });
  const token = await mint('A', sessionClaims('secret-group'));
  assert.equal(await gate.identifyOrNull({ headers: [['Cookie', `__Host-tinysesam_gate=${token}`]] }), null);
  assert.equal(await gate.identifyOrNull({ headers: [] }), null, 'no token');
  assert.deepEqual(events, [{ code: 'issuer', kid: publicJwk('A').kid }]);
  const text = JSON.stringify(events);
  assert.ok(!text.includes(token.slice(0, 20)) && !text.includes('secret-group') && !text.includes('anna'));
  // A throwing logger does not change the answer.
  const throwing = new Gate({
    mode: 'header',
    logger: () => {
      throw new Error('x');
    },
  });
  assert.equal(await throwing.identifyOrNull({ headers: [['Remote-User', 'a\u0001']] }), null);
});

test('an unexpected failure inside the client fails closed as internal', async () => {
  const gate = new Gate({
    mode: 'token',
    rules: { issuer: DEFAULTS.issuer, audience: DEFAULTS.audience, leeway: 0 },
    keys: {
      lookup: async () => {
        throw new TypeError('boom');
      },
    },
    now: () => DEFAULTS.now,
  });
  const internal = (err: unknown) => err instanceof GateError && err.code === 'internal';
  await assert.rejects(gate.verify(await mint('A', sessionClaims())), internal);
  await assert.rejects(
    gate.identify({ headers: [['Cookie', `__Host-tinysesam_gate=${await mint('A', sessionClaims())}`]] }),
    internal,
  );
  const broken = {
    [Symbol.iterator]: () => {
      throw new Error('boom');
    },
  };
  await assert.rejects((await createGate({ mode: 'header' })).identify({ headers: broken }), internal);
});

test('top bar fetch: only TinySesam cookies go out, any failure is signed out', async () => {
  // A slot that is not shown stays null even with a safe href.
  const hidden = parseTopbar(
    JSON.stringify({
      signed_in: true,
      name: 'A',
      account: { shown: false, href: '/a' },
      admin_panel: { shown: 'yes', href: '/b' },
    }),
  );
  assert.equal(hidden.account, null);
  assert.equal(hidden.admin_panel, null);
  assert.equal(
    tinysesamCookies('a=1; tinysesam_session=s; __Host-tinysesam_gate=g; other=2'),
    'tinysesam_session=s; __Host-tinysesam_gate=g',
  );
  let seen = '';
  const server = createServer((req, res) => {
    seen = req.headers.cookie ?? '';
    if (req.url === '/fail') {
      res.writeHead(500);
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        brand: 'B',
        signed_in: true,
        name: 'Anna',
        links: [{ title: 'x', href: 'javascript:alert(1)' }],
        logout: { href: '/auth/logout' },
      }),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  try {
    const bar = await fetchTopbar(`http://127.0.0.1:${port}/auth/topbar.json`, 'a=1; tinysesam_session=s');
    assert.equal(seen, 'tinysesam_session=s');
    assert.deepEqual(bar, {
      brand: 'B',
      signed_in: true,
      name: 'Anna',
      links: [],
      menu_links: [],
      account: null,
      admin_panel: null,
      logout: '/auth/logout',
      approvals: null,
      frame: { layout: 'top', name: null, icon: null, home: null, links: [] },
    });
    assert.equal((await fetchTopbar(`http://127.0.0.1:${port}/fail`, null)).signed_in, false);
    assert.equal((await fetchTopbar('http://127.0.0.1:1/none', null)).signed_in, false);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

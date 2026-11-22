// What the vectors cannot carry (spec section 5): a real HTTP server that never answers, a body above 64 KiB, 32
// concurrent requests sharing one fetch, no redirects — through the platform's fetch and the key set cache.

import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { test } from 'node:test';
import { createGate, Gate } from '../src/gate.ts';
import { FETCH_TIMEOUT_MS, httpFetcher, JwksCache, MAX_JWKS_BYTES } from '../src/jwks.ts';
import { DEFAULTS, kidOf, mint, outcome, publicJwk, sessionClaims } from './helpers.ts';

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

/** A server on a loopback port; every open socket is destroyed when it closes. */
async function serve(handler: Handler): Promise<{ url: string; hits: () => number; close: () => Promise<void> }> {
  let hits = 0;
  const sockets = new Set<Socket>();
  const server: Server = createServer((req, res) => {
    hits++;
    handler(req, res);
  });
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/auth/gate/jwks.json`,
    hits: () => hits,
    close: async () => {
      for (const s of sockets) {
        s.destroy();
      }
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

const JWKS = JSON.stringify({ keys: [publicJwk('A')] });

/** A gate at the vectors' clock over a cache that fetches url (deadline in ms, at most the specification's 5 s). */
function gateFor(url: string, timeoutMs?: number): Gate {
  const cache = new JwksCache(httpFetcher(url), { clock: () => 0, ...(timeoutMs ? { timeoutMs } : {}) });
  return new Gate({
    mode: 'token',
    rules: { issuer: DEFAULTS.issuer, audience: DEFAULTS.audience, leeway: 0 },
    keys: cache,
    now: () => DEFAULTS.now,
  });
}

test('a server that accepts and never answers: the request returns after the 5 s deadline and fails closed', async () => {
  const srv = await serve(() => {
    /* never answers */
  });
  try {
    const gate = await createGate({
      mode: 'token',
      issuer: DEFAULTS.issuer,
      audience: DEFAULTS.audience,
      jwksUrl: srv.url,
    });
    const token = await mint('A', sessionClaims());
    const started = performance.now();
    assert.equal(await outcome(gate.verify(token)), 'key_unavailable');
    const waited = performance.now() - started;
    assert.ok(waited >= FETCH_TIMEOUT_MS - 100 && waited < FETCH_TIMEOUT_MS + 1500, `waited ${waited} ms`);
    // The next request does not wait again: one attempt per 10 s, no set → key_unavailable at once.
    const again = performance.now();
    assert.equal(await outcome(gate.verify(token)), 'key_unavailable');
    assert.ok(performance.now() - again < 200, 'the second request waited for keys');
    assert.equal(srv.hits(), 1);
  } finally {
    await srv.close();
  }
});

test('a server that sends headers and then stalls the body: the deadline covers the body too', async () => {
  const srv = await serve((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write('{"keys":[');
  });
  try {
    const gate = gateFor(srv.url, 400);
    const started = performance.now();
    assert.equal(await outcome(gate.verify(await mint('A', sessionClaims()))), 'key_unavailable');
    assert.ok(performance.now() - started < 1500);
  } finally {
    await srv.close();
  }
});

test('a body above 64 KiB is a failed fetch; exactly 64 KiB is accepted', async () => {
  for (const [extra, want] of [
    [0, 'ok'],
    [1, 'key_unavailable'],
    [1024 * 1024, 'key_unavailable'],
  ] as const) {
    const body = JWKS + ' '.repeat(MAX_JWKS_BYTES - JWKS.length + extra);
    const srv = await serve((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(body);
    });
    try {
      const gate = gateFor(srv.url);
      assert.equal(await outcome(gate.verify(await mint('A', sessionClaims()))), want, `${body.length} bytes`);
    } finally {
      await srv.close();
    }
  }
});

test('32 concurrent requests share one fetch', async () => {
  let release: () => void = () => undefined;
  const gateOpen = new Promise<void>((resolve) => {
    release = resolve;
  });
  const srv = await serve((_req, res) => {
    gateOpen.then(() => {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'max-age=600' });
      res.end(JWKS);
    });
  });
  try {
    const gate = gateFor(srv.url);
    const token = await mint('A', sessionClaims());
    const all = Promise.all(Array.from({ length: 32 }, () => outcome(gate.verify(token))));
    setTimeout(release, 100);
    assert.deepEqual(await all, Array(32).fill('ok'));
    assert.equal(srv.hits(), 1);
  } finally {
    await srv.close();
  }
});

test('no redirects: a redirect to a valid key set is a failed fetch', async () => {
  const target = await serve((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JWKS);
  });
  const srv = await serve((req, res) => {
    if (req.url === '/auth/gate/jwks.json') {
      res.writeHead(302, { location: target.url });
      res.end();
    }
  });
  try {
    assert.equal(await outcome(gateFor(srv.url).verify(await mint('A', sessionClaims()))), 'key_unavailable');
    assert.equal(target.hits(), 0, 'the redirect was followed');
  } finally {
    await srv.close();
    await target.close();
  }
});

test('a status other than 200 and a body that is no JSON are failed fetches', async () => {
  for (const [status, body] of [
    [500, JWKS],
    [404, JWKS],
    [200, 'not json'],
    [200, '{"keys":[]}'],
  ] as const) {
    const srv = await serve((_req, res) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(body);
    });
    try {
      assert.equal(
        await outcome(gateFor(srv.url).verify(await mint('A', sessionClaims()))),
        'key_unavailable',
        `${status} ${body}`,
      );
    } finally {
      await srv.close();
    }
  }
});

test('createGate with jwksUrl: a fetched key set verifies, a foreign key does not', async () => {
  const srv = await serve((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'max-age=300' });
    res.end(JWKS);
  });
  try {
    // The wall clock: mint the claims for now.
    const now = Math.floor(Date.now() / 1000);
    const gate = await createGate({
      mode: 'token',
      issuer: DEFAULTS.issuer,
      audience: DEFAULTS.audience,
      jwksUrl: srv.url,
    });
    const ok = await gate.verify(await mint('A', sessionClaims('editors', now)));
    assert.equal(ok.identity.user, 'anna');
    assert.equal(await outcome(gate.verify(await mint('X', sessionClaims('editors', now)))), 'kid');
    assert.equal(kidOf('A').length, 16);
    assert.equal(srv.hits(), 1, 'the unknown kid within 10 s of the last fetch must not fetch again');
  } finally {
    await srv.close();
  }
});

test('the fetcher itself stops reading above 64 KiB (it does not read the whole body first)', async () => {
  const srv = await serve((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JWKS + ' '.repeat(MAX_JWKS_BYTES - JWKS.length + 1));
  });
  try {
    await assert.rejects(httpFetcher(srv.url)(AbortSignal.timeout(FETCH_TIMEOUT_MS)), /larger than the limit/);
    const exact = await serve((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JWKS + ' '.repeat(MAX_JWKS_BYTES - JWKS.length));
    });
    try {
      const r = await httpFetcher(exact.url)(AbortSignal.timeout(FETCH_TIMEOUT_MS));
      assert.equal(r.body.length, MAX_JWKS_BYTES);
    } finally {
      await exact.close();
    }
  } finally {
    await srv.close();
  }
});

test('at the deadline the fetch is aborted: the connection to a silent server is closed, not left open', async () => {
  let closedAfter = -1;
  const started = performance.now();
  const srv = await serve((req) => {
    req.socket.on('close', () => {
      closedAfter = performance.now() - started;
    });
  });
  try {
    assert.equal(await outcome(gateFor(srv.url, 300).verify(await mint('A', sessionClaims()))), 'key_unavailable');
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.ok(closedAfter >= 0 && closedAfter < 1500, `connection closed after ${closedAfter} ms`);
  } finally {
    await srv.close();
  }
});
